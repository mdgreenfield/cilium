// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/trigger"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ec2metadata"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/sirupsen/logrus"
)

const (
	defaultPreAllocation = 8
)

var (
	ec2Client         *ec2.EC2
	metadataClient    *ec2metadata.EC2Metadata
	identityDocument  *ec2metadata.EC2InstanceIdentityDocument
	allocationTrigger *trigger.Trigger
)

type instance struct {
	enis map[string]*v2.ENI
}

type instanceMap map[string]*instance

func (m instanceMap) add(instanceID string, eni *v2.ENI) {
	i, ok := m[instanceID]
	if !ok {
		i = &instance{}
		m[instanceID] = i
	}

	if i.enis == nil {
		i.enis = map[string]*v2.ENI{}
	}

	i.enis[eni.ID] = eni
}

type tags map[string]string

func (t tags) match(required tags) bool {
	for k, neededvalue := range required {
		haveValue, ok := t[k]
		if !ok || (ok && neededvalue != haveValue) {
			return false
		}
	}
	return true
}

type subnet struct {
	ID                 string
	Name               string
	CIDR               string
	AvailabilityZone   string
	VpcID              string
	AvailableAddresses int
	Tags               tags
}

type subnetMap map[string]*subnet

type instancesManager struct {
	mutex     lock.RWMutex
	instances instanceMap
	subnets   subnetMap
}

func (m *instancesManager) getSubnet(subnetID string) *subnet {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.subnets[subnetID]
}

func (m *instancesManager) findSubnetByTags(vpcID, availabilityZone string, required tags) (bestSubnet *subnet) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, s := range m.subnets {
		if s.VpcID == vpcID && s.AvailabilityZone == availabilityZone && s.Tags.match(required) {
			if bestSubnet == nil || bestSubnet.AvailableAddresses < s.AvailableAddresses {
				bestSubnet = s
			}
		}
	}

	return
}

func (m *instancesManager) resync() {
	instances, vpcs, err := getInstanceInterfaces()
	if err != nil {
		log.WithError(err).Warning("Unable to synchronize EC2 interface list")
		return
	}

	subnets, err := getSubnets(vpcs)
	if err != nil {
		log.WithError(err).Warning("Unable to retrieve EC2 subnets list")
		return
	}

	log.Infof("Synchronized %d ENIs and %d subnets", len(instances), len(subnets))

	m.mutex.Lock()
	m.instances = instances
	m.subnets = subnets
	m.mutex.Unlock()
}

func (m *instancesManager) getENIs(instanceID string) []*v2.ENI {
	enis := []*v2.ENI{}

	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if i, ok := m.instances[instanceID]; ok {
		for _, e := range i.enis {
			enis = append(enis, e.DeepCopy())
		}
	}

	return enis
}

var instances = instancesManager{instances: instanceMap{}}

type ciliumNode struct {
	name            string
	neededAddresses int
	resource        *v2.CiliumNode
}

type ciliumNodeMap map[string]*ciliumNode

type nodeManager struct {
	mutex lock.RWMutex
	nodes ciliumNodeMap
}

var ciliumNodes = nodeManager{nodes: ciliumNodeMap{}}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func indexExists(enis []*v2.ENI, index int64) bool {
	for _, e := range enis {
		if e.Number == int(index) {
			return true
		}
	}
	return false
}

func (n *ciliumNode) allocateENI(s *subnet, enis []*v2.ENI) {
	scopedLog := log.WithFields(logrus.Fields{
		"instanceID":     n.resource.Spec.ENI.InstanceID,
		"securityGroups": n.resource.Spec.ENI.SecurityGroups,
		"subnetID":       s.ID,
	})

	log.Infof("Allocating ENI")

	createReq := &ec2.CreateNetworkInterfaceInput{}
	desc := "Cilium-CNI (" + n.resource.Spec.ENI.InstanceID + ")"
	createReq.Description = &desc
	for _, grp := range n.resource.Spec.ENI.SecurityGroups {
		createReq.Groups = append(createReq.Groups, grp)
	}

	subnetID := s.ID
	createReq.SubnetId = &subnetID

	resp, err := ec2Client.CreateNetworkInterfaceRequest(createReq).Send()
	if err != nil {
		scopedLog.WithError(err).Warning("Unable to create ENI")
		return
	}

	eniID := *resp.NetworkInterface.NetworkInterfaceId
	scopedLog = scopedLog.WithField("eniID", eniID)
	scopedLog.Info("Created new ENI")

	var index int64
	for indexExists(enis, index) {
		index++
	}

	attachReq := &ec2.AttachNetworkInterfaceInput{}
	attachReq.DeviceIndex = &index
	instanceID := n.resource.Spec.ENI.InstanceID
	attachReq.InstanceId = &instanceID
	attachReq.NetworkInterfaceId = &eniID

	attachResp, err := ec2Client.AttachNetworkInterfaceRequest(attachReq).Send()
	if err != nil {
		delReq := &ec2.DeleteNetworkInterfaceInput{}
		delReq.NetworkInterfaceId = &eniID

		_, delErr := ec2Client.DeleteNetworkInterfaceRequest(delReq).Send()
		if delErr != nil {
			scopedLog.WithError(delErr).Warning("Unable to undo ENI creation after failure to attach")
		}

		scopedLog.WithError(err).Warningf("Unable to attach ENI at index %d", index)
		return
	}

	scopedLog = scopedLog.WithFields(logrus.Fields{
		"attachmentID": *attachResp.AttachmentId,
		"index":        index,
	})
	scopedLog.Info("Attached ENI to instance")

	// We have an attachment ID from the last API, which lets us mark the
	// interface as delete on termination
	changes := &ec2.NetworkInterfaceAttachmentChanges{}
	aID := *attachResp.AttachmentId
	changes.AttachmentId = &aID
	enable := true
	changes.DeleteOnTermination = &enable
	modifyReq := &ec2.ModifyNetworkInterfaceAttributeInput{}
	modifyReq.Attachment = changes
	modifyReq.NetworkInterfaceId = &eniID

	_, err = ec2Client.ModifyNetworkInterfaceAttributeRequest(modifyReq).Send()
	if err != nil {
		log.WithError(err).Warning("Unable to mark ENI for deletion on termination")
	}
}

// limit contains limits for adapter count and addresses
//
// Stolen from github.com/lfyt/cni-ipvlan-vpc-k8s/
type limit struct {
	Adapters int
	IPv4     int
	IPv6     int
}

var eniLimits = map[string]limit{
	"c1.medium":     {2, 6, 0},
	"c1.xlarge":     {4, 15, 0},
	"c3.large":      {3, 10, 10},
	"c3.xlarge":     {4, 15, 15},
	"c3.2xlarge":    {4, 15, 15},
	"c3.4xlarge":    {8, 30, 30},
	"c3.8xlarge":    {8, 30, 30},
	"c4.large":      {3, 10, 10},
	"c4.xlarge":     {4, 15, 15},
	"c4.2xlarge":    {4, 15, 15},
	"c4.4xlarge":    {8, 30, 30},
	"c4.8xlarge":    {8, 30, 30},
	"c5.large":      {3, 10, 10},
	"c5d.large":     {3, 10, 10},
	"c5n.large":     {3, 10, 10},
	"c5.xlarge":     {4, 15, 15},
	"c5d.xlarge":    {4, 15, 15},
	"c5n.xlarge":    {4, 15, 15},
	"c5.2xlarge":    {4, 15, 15},
	"c5d.2xlarge":   {4, 15, 15},
	"c5n.2xlarge":   {4, 15, 15},
	"c5.4xlarge":    {8, 30, 30},
	"c5d.4xlarge":   {8, 30, 30},
	"c5n.4xlarge":   {8, 30, 30},
	"c5.9xlarge":    {8, 30, 30},
	"c5d.9xlarge":   {8, 30, 30},
	"c5n.9xlarge":   {8, 30, 30},
	"c5.18xlarge":   {15, 50, 50},
	"c5d.18xlarge":  {15, 50, 50},
	"c5n.18xlarge":  {15, 50, 50},
	"cc2.8xlarge":   {8, 30, 0},
	"cg1.4xlarge":   {8, 30, 0},
	"cr1.8xlarge":   {8, 30, 0},
	"d2.xlarge":     {4, 15, 15},
	"d2.2xlarge":    {4, 15, 15},
	"d2.4xlarge":    {8, 30, 30},
	"d2.8xlarge":    {8, 30, 30},
	"f1.2xlarge":    {4, 15, 15},
	"f1.16xlarge":   {8, 50, 50},
	"g2.2xlarge":    {4, 15, 0},
	"g2.8xlarge":    {8, 30, 0},
	"g3.4xlarge":    {8, 30, 30},
	"g3.8xlarge":    {8, 30, 30},
	"g3.16xlarge":   {15, 50, 50},
	"h1.2xlarge":    {4, 15, 15},
	"h1.4xlarge":    {8, 30, 30},
	"h1.8xlarge":    {8, 30, 30},
	"h1.16xlarge":   {15, 50, 50},
	"hi1.4xlarge":   {8, 30, 0},
	"hs1.8xlarge":   {8, 30, 0},
	"i2.xlarge":     {4, 15, 15},
	"i2.2xlarge":    {4, 15, 15},
	"i2.4xlarge":    {8, 30, 30},
	"i2.8xlarge":    {8, 30, 30},
	"i3.large":      {3, 10, 10},
	"i3.xlarge":     {4, 15, 15},
	"i3.2xlarge":    {4, 15, 15},
	"i3.4xlarge":    {8, 30, 30},
	"i3.8xlarge":    {8, 30, 30},
	"i3.16xlarge":   {15, 50, 50},
	"i3.metal":      {15, 50, 50},
	"m1.small":      {2, 4, 0},
	"m1.medium":     {2, 6, 0},
	"m1.large":      {3, 10, 0},
	"m1.xlarge":     {4, 15, 0},
	"m2.xlarge":     {4, 15, 0},
	"m2.2xlarge":    {4, 30, 0},
	"m2.4xlarge":    {8, 30, 0},
	"m3.medium":     {2, 6, 0},
	"m3.large":      {3, 10, 0},
	"m3.xlarge":     {4, 15, 0},
	"m3.2xlarge":    {4, 30, 0},
	"m4.large":      {2, 10, 10},
	"m4.xlarge":     {4, 15, 15},
	"m4.2xlarge":    {4, 15, 15},
	"m4.4xlarge":    {8, 30, 30},
	"m4.10xlarge":   {8, 30, 30},
	"m4.16xlarge":   {8, 30, 30},
	"m5.large":      {3, 10, 10},
	"m5a.large":     {3, 10, 10},
	"m5d.large":     {3, 10, 10},
	"m5.xlarge":     {4, 15, 15},
	"m5a.xlarge":    {4, 15, 15},
	"m5d.xlarge":    {4, 15, 15},
	"m5.2xlarge":    {4, 15, 15},
	"m5a.2xlarge":   {4, 15, 15},
	"m5d.2xlarge":   {4, 15, 15},
	"m5.4xlarge":    {8, 30, 30},
	"m5a.4xlarge":   {8, 30, 30},
	"m5d.4xlarge":   {8, 30, 30},
	"m5.12xlarge":   {8, 30, 30},
	"m5a.12xlarge":  {8, 30, 30},
	"m5d.12xlarge":  {8, 30, 30},
	"m5.24xlarge":   {15, 50, 50},
	"m5a.24xlarge":  {15, 50, 50},
	"m5d.24xlarge":  {15, 50, 50},
	"p2.xlarge":     {4, 15, 15},
	"p2.8xlarge":    {8, 30, 30},
	"p2.16xlarge":   {8, 30, 30},
	"p3.2xlarge":    {4, 15, 15},
	"p3.8xlarge":    {8, 30, 30},
	"p3.16xlarge":   {8, 30, 30},
	"p3dn.24xlarge": {15, 50, 50},
	"r3.large":      {3, 10, 10},
	"r3.xlarge":     {4, 15, 15},
	"r3.2xlarge":    {4, 15, 15},
	"r3.4xlarge":    {8, 30, 30},
	"r3.8xlarge":    {8, 30, 30},
	"r4.large":      {3, 10, 10},
	"r4.xlarge":     {4, 15, 15},
	"r4.2xlarge":    {4, 15, 15},
	"r4.4xlarge":    {8, 30, 30},
	"r4.8xlarge":    {8, 30, 30},
	"r4.16xlarge":   {15, 50, 50},
	"r5.large":      {3, 10, 10},
	"r5d.large":     {3, 10, 10},
	"r5a.large":     {3, 10, 10},
	"r5.xlarge":     {4, 15, 15},
	"r5a.xlarge":    {4, 15, 15},
	"r5d.xlarge":    {4, 15, 15},
	"r5.2xlarge":    {4, 15, 15},
	"r5a.2xlarge":   {4, 15, 15},
	"r5d.2xlarge":   {4, 15, 15},
	"r5.4xlarge":    {8, 30, 30},
	"r5a.4xlarge":   {8, 30, 30},
	"r5d.4xlarge":   {8, 30, 30},
	"r5.12xlarge":   {8, 30, 30},
	"r5a.12xlarge":  {8, 30, 30},
	"r5d.12xlarge":  {8, 30, 30},
	"r5.24xlarge":   {15, 50, 50},
	"r5a.24xlarge":  {15, 50, 50},
	"r5d.24xlarge":  {15, 50, 50},
	"t1.micro":      {2, 2, 0},
	"t2.nano":       {2, 2, 2},
	"t2.micro":      {2, 2, 2},
	"t2.small":      {2, 4, 4},
	"t2.medium":     {3, 6, 6},
	"t2.large":      {3, 12, 12},
	"t2.xlarge":     {3, 15, 15},
	"t2.2xlarge":    {3, 15, 15},
	"x1e.xlarge":    {3, 10, 10},
	"x1e.2xlarge":   {4, 15, 15},
	"x1e.4xlarge":   {4, 15, 15},
	"x1e.8xlarge":   {4, 15, 15},
	"x1.16xlarge":   {8, 30, 30},
	"x1e.16xlarge":  {8, 30, 30},
	"x1.32xlarge":   {8, 30, 30},
	"x1e.32xlarge":  {8, 30, 30},
	"z1d.large":     {3, 10, 10},
	"z1d.xlarge":    {4, 15, 15},
	"z1d.2xlarge":   {4, 15, 15},
	"z1d.3xlarge":   {8, 30, 30},
	"z1d.6xlarge":   {8, 30, 30},
	"z1d.12xlarge":  {15, 50, 50},
}

func (n *ciliumNode) canAllocate(enis []*v2.ENI, limits limit, neededAddresses int) (*v2.ENI, *subnet, int) {
	for _, e := range enis {
		if e.Number >= n.resource.Spec.ENI.FirstInterfaceIndex && len(e.Addresses) < limits.IPv4 {
			if subnet := instances.getSubnet(e.Subnet.ID); subnet != nil {
				if subnet.AvailableAddresses > 0 {
					return e, subnet, min(subnet.AvailableAddresses, neededAddresses)
				}
			}
		}
	}

	return nil, nil, 0
}

func (n *ciliumNode) allocate() {
	scopedLog := log.WithField("node", n.name)

	instanceType := n.resource.Spec.ENI.InstanceType
	limits, ok := eniLimits[instanceType]
	if !ok {
		log.Warning("Unable to determine limits of instance type '%s'", instanceType)
	}

	enis := instances.getENIs(n.resource.Spec.ENI.InstanceID)
	if len(enis) == 0 {
		return
	}

	if e, subnet, available := n.canAllocate(enis, limits, n.neededAddresses); subnet != nil {
		scopedLog = scopedLog.WithFields(logrus.Fields{
			"limit":        limits.IPv4,
			"eniID":        e.ID,
			"subnetID":     subnet.ID,
			"availableIPs": subnet.AvailableAddresses,
			"neededIPs":    n.neededAddresses,
		})

		scopedLog.Infof("Allocating IP on existing ENI")

		request := ec2.AssignPrivateIpAddressesInput{}
		request.NetworkInterfaceId = &e.ID
		available64 := int64(available)
		request.SecondaryPrivateIpAddressCount = &available64

		if _, err := ec2Client.AssignPrivateIpAddressesRequest(&request).Send(); err != nil {
			scopedLog.WithError(err).Warningf("Unable to assign %d additional private IPs to ENI %s", available, e.ID)
		}

		// IPs were allocated, they will be picked up with the next refresh
		go func() {
			instances.resync()
		}()

		return
	}

	scopedLog = scopedLog.WithFields(logrus.Fields{
		"vpcID":            enis[0].VPC.ID,
		"availabilityZone": n.resource.Spec.ENI.AvailabilityZone,
		"subnetTags":       n.resource.Spec.ENI.SubnetTags,
	})
	scopedLog.Infof("No more IPs available, creating new ENI")

	if len(enis) >= limits.Adapters {
		log.Warningf("Instance %s is out of ENIs", n.resource.Spec.ENI.InstanceID)
		return
	}

	bestSubnet := instances.findSubnetByTags(enis[0].VPC.ID, n.resource.Spec.ENI.AvailabilityZone, n.resource.Spec.ENI.SubnetTags)
	if bestSubnet == nil {
		scopedLog.Warning("No subnets available to allocate ENI")
		return
	}

	n.allocateENI(bestSubnet, enis)

	// ENI was allocated, resync
	go func() {
		instances.resync()
	}()
}

func (n *ciliumNode) refresh() {
	if n.neededAddresses > 0 {
		if allocationTrigger != nil {
			allocationTrigger.TriggerWithReason(n.name)
		}
	}

	node := n.resource.DeepCopy()

	if node.Spec.IPAM.Available == nil {
		node.Spec.IPAM.Available = map[string]v2.AllocationIP{}
	}

	if node.Status.IPAM.InUse == nil {
		node.Status.IPAM.InUse = map[string]v2.AllocationIP{}
	}

	relevantENIs := instances.getENIs(n.resource.Spec.ENI.InstanceID)
	node.Status.ENI.ENIs = map[string]v2.ENI{}
	node.Spec.IPAM.Available = map[string]v2.AllocationIP{}
	for _, e := range relevantENIs {
		node.Status.ENI.ENIs[e.ID] = *e

		if e.Number < node.Spec.ENI.FirstInterfaceIndex {
			continue
		}

		for _, ip := range e.Addresses {
			node.Spec.IPAM.Available[ip] = v2.AllocationIP{Resource: e.ID}
		}
	}

	var statusErr, specErr error
	var newNode *v2.CiliumNode

	// If k8s supports status as a sub-resource, then we need to update the status separately
	k8sCapabilities := k8sversion.Capabilities()
	switch {
	case k8sCapabilities.UpdateStatus:
		if !reflect.DeepEqual(n.resource.Spec, node.Spec) {
			for retry := 0; retry < 2; retry++ {
				newNode, specErr = ciliumK8sClient.CiliumV2().CiliumNodes("default").Update(node)
				if newNode != nil {
					n.resource = newNode
				}
				if specErr == nil {
					break
				}
			}
		}

		if !reflect.DeepEqual(n.resource.Status, node.Status) {
			for retry := 0; retry < 2; retry++ {
				newNode, statusErr = ciliumK8sClient.CiliumV2().CiliumNodes("default").UpdateStatus(node)
				if newNode != nil {
					n.resource = newNode
				}
				if statusErr == nil {
					break
				}
			}
		}
	default:
		if !reflect.DeepEqual(n.resource, node) {
			for retry := 0; retry < 2; retry++ {
				newNode, specErr = ciliumK8sClient.CiliumV2().CiliumNodes("default").Update(node)
				if newNode != nil {
					n.resource = newNode
				}
				if specErr == nil {
					break
				}
			}
		}
	}

	if specErr != nil {
		log.WithError(specErr).Warningf("Unable to update spec of CiliumNode %s", node.Name)
	}

	if statusErr != nil {
		log.WithError(statusErr).Warningf("Unable to update status of CiliumNode %s", node.Name)
	}
}

func (n *nodeManager) Update(resource *v2.CiliumNode) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	node, ok := n.nodes[resource.Name]
	if !ok {
		node = &ciliumNode{
			name: resource.Name,
		}
		n.nodes[node.name] = node
	}
	node.resource = resource

	requiredAddresses := resource.Spec.ENI.PreAllocate
	if requiredAddresses == 0 {
		requiredAddresses = defaultPreAllocation
	}

	availableIPs := len(resource.Spec.IPAM.Available)
	usedIPs := len(resource.Status.IPAM.InUse)
	node.neededAddresses = requiredAddresses - (availableIPs - usedIPs)
	if node.neededAddresses > 0 {
		if allocationTrigger != nil {
			allocationTrigger.TriggerWithReason(node.name)
		}
	}

	log.WithFields(logrus.Fields{
		"instanceID":      resource.Spec.ENI.InstanceID,
		"addressesNeeded": node.neededAddresses,
	}).Infof("Updated node %s", resource.Name)
}

func (n *nodeManager) Delete(nodeName string) {
	n.mutex.Lock()
	delete(n.nodes, nodeName)
	n.mutex.Unlock()
}

func (n *nodeManager) allocateForNode(nodeName string) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	node, ok := n.nodes[nodeName]
	if ok {
		node.allocate()
	}
}

func (n *nodeManager) refresh() {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	for _, node := range n.nodes {
		node.refresh()
	}
}

func newEc2Filter(name string, values ...string) *ec2.Filter {
	filter := &ec2.Filter{
		Name: aws.String(name),
	}
	for _, value := range values {
		filter.Values = append(filter.Values, value)
	}
	return filter
}

func parseAndAddENI(iface *ec2.NetworkInterface, instances instanceMap, vpcs map[string]string) error {
	var availabilityZone, instanceID string

	if iface.PrivateIpAddress == nil {
		return fmt.Errorf("ENI has no IP address")
	}

	eni := v2.ENI{
		IP:             *iface.PrivateIpAddress,
		SecurityGroups: []string{},
		Addresses:      []string{},
	}

	if iface.AvailabilityZone != nil {
		availabilityZone = *iface.AvailabilityZone
	}

	if iface.MacAddress != nil {
		eni.MAC = *iface.MacAddress
	}

	if iface.NetworkInterfaceId != nil {
		eni.ID = *iface.NetworkInterfaceId
	}

	if iface.Description != nil {
		eni.Description = *iface.Description
	}

	if iface.Attachment != nil {
		if iface.Attachment.DeviceIndex != nil {
			eni.Number = int(*iface.Attachment.DeviceIndex)
		}

		if iface.Attachment.InstanceId != nil {
			instanceID = *iface.Attachment.InstanceId
		}
	}

	if iface.SubnetId != nil {
		eni.Subnet.ID = *iface.SubnetId
	}

	if iface.VpcId != nil {
		eni.VPC.ID = *iface.VpcId
	}

	for _, ip := range iface.PrivateIpAddresses {
		if ip.PrivateIpAddress != nil {
			eni.Addresses = append(eni.Addresses, *ip.PrivateIpAddress)
		}
	}

	//	for _, ip := range iface.Ipv6Addresses {
	//		if ip.Ipv6Address {
	//			eni.Addresses = append(eni.Addresses, *ip.Ipv6Address)
	//		}
	//	}

	for _, g := range iface.Groups {
		if g.GroupId != nil {
			eni.SecurityGroups = append(eni.SecurityGroups, *g.GroupId)
		}
	}

	instances.add(instanceID, &eni)
	vpcs[eni.VPC.ID] = availabilityZone
	return nil
}

func getInstanceInterfaces() (instanceMap, map[string]string, error) {
	instances := instanceMap{}
	vpcs := map[string]string{}

	req := ec2.DescribeNetworkInterfacesInput{}
	response, err := ec2Client.DescribeNetworkInterfacesRequest(&req).Send()
	if err != nil {
		return nil, nil, err
	}

	for _, iface := range response.NetworkInterfaces {
		err := parseAndAddENI(&iface, instances, vpcs)
		if err != nil {
			log.WithError(err).Warning("Unable to convert NetworkInterface to internal representation")
		}
	}

	return instances, vpcs, nil
}

func getSubnets(vpcs map[string]string) (subnetMap, error) {
	subnets := subnetMap{}

	input := &ec2.DescribeSubnetsInput{}
	result, err := ec2Client.DescribeSubnetsRequest(input).Send()
	if err != nil {
		return nil, err
	}

	for _, s := range result.Subnets {
		subnet := &subnet{
			ID:                 *s.SubnetId,
			CIDR:               *s.CidrBlock,
			AvailableAddresses: int(*s.AvailableIpAddressCount),
			Tags:               map[string]string{},
		}

		if s.AvailabilityZone != nil {
			subnet.AvailabilityZone = *s.AvailabilityZone
		}

		if s.VpcId != nil {
			subnet.VpcID = *s.VpcId
		}

		for _, tag := range s.Tags {
			if *tag.Key == "Name" {
				subnet.Name = *tag.Value
			} else {
				subnet.Tags[*tag.Key] = *tag.Value
			}
		}

		subnets[subnet.ID] = subnet
	}

	return subnets, nil
}

func allocateTrigger(reasons []string) {
	for _, nodeName := range reasons {
		ciliumNodes.allocateForNode(nodeName)
	}
}

func startENIAllocator() error {
	log.Info("Starting ENI allocator...")

	cfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		return fmt.Errorf("unable to load AWS configuration: %s", err)
	}

	log.Infof("Retrieving own metadata from EC2 metadata server...")

	metadataClient = ec2metadata.New(cfg)
	instance, err := metadataClient.GetInstanceIdentityDocument()
	if err != nil {
		return fmt.Errorf("unable to retrieve instance identity document: %s", err)
	}

	cfg.Region = instance.Region

	allocationTrigger, err = trigger.NewTrigger(trigger.Parameters{
		Name:        "eni-allocation",
		MinInterval: 5 * time.Second,
		TriggerFunc: allocateTrigger,
	})
	if err != nil {
		return fmt.Errorf("unable to initialize trigger: %s", err)
	}

	identityDocument = &instance
	ec2Client = ec2.New(cfg)

	log.Infof("Connected to metadata server")

	instances.resync()
	ciliumNodes.refresh()

	log.Info("Starting ENI operator...")
	mngr := controller.NewManager()
	mngr.UpdateController("eni-refresh",
		controller.ControllerParams{
			RunInterval: time.Minute,
			DoFunc: func(_ context.Context) error {
				log.Debugf("Refreshing CiliumNode resources...")
				instances.resync()
				ciliumNodes.refresh()
				return nil
			},
		})

	return nil
}
