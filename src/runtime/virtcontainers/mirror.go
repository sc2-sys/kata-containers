package virtcontainers

import (
    "time"
    "net"
	"fmt"
	"sync"
    "crypto/sha256"
    "encoding/hex"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// MirrorRoutineController manages the lifecycle of the mirroring goroutines.
type MirrorRoutineController struct {
	stopChs []chan struct{}
	wg      sync.WaitGroup
}

// NewMirrorRoutineController creates a new instance of MirrorRoutineController.
func NewMirrorRoutineController() *MirrorRoutineController {
	return &MirrorRoutineController{
		stopChs: make([]chan struct{}, 0),
	}
}

// AddStopChannel adds a stop channel to the controller.
func (mrc *MirrorRoutineController) AddStopChannel(stopCh chan struct{}) {
	mrc.stopChs = append(mrc.stopChs, stopCh)
}

// Stop stops all running goroutines managed by the controller.
func (mrc *MirrorRoutineController) Stop() {
	for _, ch := range mrc.stopChs {
		close(ch)
	}
	mrc.wg.Wait()
}

func getPacketID(pkt gopacket.Packet) string {
	hash := sha256.New()

	// Extract key attributes from the packet
	var srcIP, dstIP string
	var srcPort, dstPort uint16
	var protocol string
	var uniqueID string

	// Extract IP layer
	if ipLayer := pkt.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		uniqueID = fmt.Sprintf("%d", ip.Id)
		protocol = ip.Protocol.String()
	} else if ipLayer := pkt.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		protocol = ip.NextHeader.String()
	}

	// Extract transport layer
	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		uniqueID = fmt.Sprintf("%d", tcp.Seq)
	} else if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
	}

	// Combine key attributes to form a unique identifier
	idString := fmt.Sprintf("%s-%s-%d-%d-%s-%s", srcIP, dstIP, srcPort, dstPort, protocol, uniqueID)
	hash.Write([]byte(idString))
	hash.Write(pkt.Data())
	return hex.EncodeToString(hash.Sum(nil))
}

// logPacket logs the packet details using networkLogger.
func logPacket(packet gopacket.Packet) string {
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return ""
	}

    pktID := getPacketID(packet)
    srcIP := ""
	dstIP := ""
	proto := int(networkLayer.LayerType())

	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip4, _ := ip4Layer.(*layers.IPv4)
		srcIP = ip4.SrcIP.String()
		dstIP = ip4.DstIP.String()
	} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6, _ := ip6Layer.(*layers.IPv6)
		srcIP = ip6.SrcIP.String()
		dstIP = ip6.DstIP.String()
	} else {
		// If not IP, get the raw bytes of the addresses and convert to string
		srcIP = net.IP(networkLayer.NetworkFlow().Src().Raw()).String()
		dstIP = net.IP(networkLayer.NetworkFlow().Dst().Raw()).String()
	}

	networkLogger().Debugf("captured packet: id=%s srcIP=%s, dstIP=%s, proto=%d, length=%d", pktID, srcIP, dstIP, proto, len(packet.Data()))
    return pktID
}

// ForwardPacket forwards a packet to the specified interface in the given namespace.
func ForwardPacket(packet gopacket.Packet, pktID string, outIface string, outNamespace string, inNamespace string, forwardedPackets *sync.Map) error {
	if pktID == "" {
		return nil
	}

	if forwardedTo, exists := forwardedPackets.LoadOrStore(pktID, outNamespace); exists {
        if forwardedTo == inNamespace {
            networkLogger().Debugf("dropped packet: %s capturedAt=%s, forwardedTo=%s", pktID, inNamespace, forwardedTo)
            return nil
        }
	}

	return doNetNS(outNamespace, func(_ ns.NetNS) error {
		handle, err := pcap.OpenLive(outIface, 65535, true, pcap.BlockForever)
        networkLogger().Debugf("forwarding packet %s from %s to %s", pktID, inNamespace, outNamespace)
		if err != nil {
			return fmt.Errorf("could not open output interface: %v", err)
		}
		defer handle.Close()

		err = handle.WritePacketData(packet.Data())
		if err != nil {
			return fmt.Errorf("could not write packet data: %v", err)
		}
		return nil
	})
}

// CaptureAndForward captures packets from the input interface and forwards them to the output interface.
func CaptureAndForward(inIface string, outIface string, inNamespace string, outNamespace string, stopCh <-chan struct{}, wg *sync.WaitGroup, forwardedPackets *sync.Map) {
	defer wg.Done()
    time.Sleep(2)
	networkLogger().Infof("Starting CaptureAndForward for %s -> %s", inIface, outIface)
	err := doNetNS(inNamespace, func(_ ns.NetNS) error {
		handle, err := pcap.OpenLive(inIface, 65535, true, pcap.BlockForever)
		if err != nil {
			networkLogger().Errorf("could not open input interface %s: %v", inIface, err)
			return err
		}
		defer handle.Close()

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		for {
			select {
			case <-stopCh:
				networkLogger().Infof("Stopping CaptureAndForward for %s -> %s", inIface, outIface)
				return nil
			case packet := <-packetSource.Packets():
                pktID := logPacket(packet) // Log the captured packet
				err = ForwardPacket(packet, pktID, outIface, outNamespace, inNamespace, forwardedPackets)
				if err != nil {
					networkLogger().Errorf("error forwarding packet from %s to %s: %v", inIface, outIface, err)
				}
			}
		}
	})
	if err != nil {
		networkLogger().Errorf("Error in CaptureAndForward for %s -> %s: %v", inIface, outIface, err)
	}
}

