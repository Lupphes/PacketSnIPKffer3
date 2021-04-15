using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PacketDotNet;
using PacketDotNet.Ieee80211;
using SharpPcap;
using SharpPcap.LibPcap;

namespace ipk_sniffer {
    public class NetworkTools {
        private static int _captured;
        private static int _neededToCapture;
        private static ICaptureDevice _device;

        public static Dictionary<string, Dictionary<string, string>> ListDevices() {
            Dictionary<string, Dictionary<string, string>> devicesDict = new Dictionary<string, Dictionary<string, string>>();

            var devices = CaptureDeviceList.Instance;
            if (devices.Count < 1) { return null; }

            foreach (var device in devices.OfType<LibPcapLiveDevice>()) {
                devicesDict[device.Name] = new Dictionary<string, string>()
                {
                    {"happyName", device.Interface.FriendlyName},
                    {"mac", device.Interface.MacAddress?.ToString()},
                    {"description", device.Interface.Description}

                };
                if (device.Addresses.Count != 0) {
                    string tempAddress = "";
                    foreach (var deviceInterface in device.Interface.Addresses) {
                        tempAddress += "\n\t   " + deviceInterface.Addr;
                    }
                    devicesDict[device.Name].Add(
                        "address", tempAddress
                    );
                } else {
                    devicesDict[device.Name].Add(
                        "address", null
                    );
                }
            }
            return devicesDict;
        }

        public static void SniffPacket(ArgumentParser arguments) {
            ICaptureDevice device = GetDeviceInfo(arguments.Device);
            _device = device;
            _neededToCapture = arguments.Num;
            if (device == null) {
                Console.WriteLine("Specified device not found");
                Environment.Exit((int)ReturnCode.ErrArguments);
            }

            try {
                const int readTimeout = 1000;
                device.Open(DeviceMode.Promiscuous, readTimeout);

                Console.WriteLine($"Connected to {device.Name}");
                device.OnPacketArrival += OnArrivalHandler;
                device.StartCapture();

                try {
                    string filter = CreateFilter(arguments);
                    device.Filter = filter;
                    Console.WriteLine(filter);
                } catch (Exception e) {
                    Console.WriteLine($"Error while constructing a filter: {e}");
                    Environment.Exit((int)ReturnCode.ErrInvalidFilter);
                }
            } catch (PcapException e) {
                Console.WriteLine($"Error in PCapLibrary: {e}");
                Console.WriteLine("Try running the script with sudo");
                Environment.Exit((int)ReturnCode.ErrPCap);
            } catch (Exception e) {
                Console.WriteLine($"General error while trying to capture packets: {e}");
                Environment.Exit((int)ReturnCode.ErrGeneralCapture);
            }

        }

        private static ICaptureDevice GetDeviceInfo(string specifiedDevice) {
            var devices = CaptureDeviceList.Instance;
            if (devices.Count < 1) { return null; }

            foreach (var device in devices.OfType<LibPcapLiveDevice>()) {
                if ((device.Name.Equals(specifiedDevice) || device.Interface.FriendlyName != null && device.Interface.FriendlyName.Equals(specifiedDevice))) {
                    return device;
                }
            }
            return null;
        }

        private static void OnArrivalHandler(object sender, CaptureEventArgs e) {
            var packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var time = e.Packet.Timeval.Date.ToString("yyyy-MM-ddTHH\\:mm\\:ss.fffzzz");
            var len = e.Packet.Data.Length;

            var tcpUdpPacket = packet.Extract<TransportPacket>();
            var icmp = packet.Extract<InternetPacket>();
            var arpPacket = packet.Extract<ArpPacket>();

            if (tcpUdpPacket != null) {
                WriteTcpOrUdp(tcpUdpPacket, time, len);
            } else if (icmp != null) {
                WriteIcmp(icmp, time, len);
            } else if (arpPacket != null) {
                Console.WriteLine($"ARP {time}: {arpPacket.SenderProtocolAddress} > {arpPacket.TargetProtocolAddress}, length {len} bytes");
            } else {
                return;
            }

            WritePacketData(packet);

            _captured++;
            if (_captured == _neededToCapture) {
                _device.StopCapture();
            }
        }

        private static void WriteTcpOrUdp(TransportPacket tcpUdpPacket, string time, int len) {
            var tcpPacket = tcpUdpPacket.Extract<TcpPacket>();
            var ipPacket = (IPPacket)tcpUdpPacket.ParentPacket;
            System.Net.IPAddress srcIp = ipPacket.SourceAddress;
            System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
            int srcPort = tcpUdpPacket.SourcePort;
            int dstPort = tcpUdpPacket.DestinationPort;

            Console.WriteLine($"{((tcpPacket != null) ? "(TCP)" : "(UDP)")} {time}: {srcIp} {srcPort} > {dstIp} {dstPort}, length {len} bytes");
        }

        private static void WriteIcmp(InternetPacket icmp, string time, int len) {
            var ipPacket = (IPPacket)icmp.ParentPacket;
            System.Net.IPAddress srcIp = ipPacket.SourceAddress;
            System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
            Console.WriteLine($"(ICMP) {time}: {srcIp} > {dstIp}, length {len} bytes");
        }

        private static void WritePacketData(Packet packet) {
            string dataHexLine = "";
            string dataAscii = "";
            string indexHex = "";
            for (int i = 1; i < packet.BytesSegment.Bytes.Length + 1; i++) {
                dataHexLine += packet.BytesSegment.Bytes[i - 1].ToString("x").PadLeft(2, '0') + " ";
                dataAscii += (packet.BytesSegment.Bytes[i - 1] >= 33 && packet.BytesSegment.Bytes[i - 1] <= 126)
                    ? Encoding.ASCII.GetString(new byte[] { packet.BytesSegment.Bytes[i - 1] })
                    : ".";

                if (i % 16 == 0) {
                    indexHex = $"0x{i:X4}: ";
                    Console.Write($"0x{i - 1:X4}: ");
                    dataAscii += "\n";
                    Console.Write(dataHexLine + dataAscii);
                    dataHexLine = "";
                    dataAscii = "";
                } else if (i % 8 == 0) {
                    dataHexLine += " ";
                    dataAscii += " ";
                }
            }

            if (dataHexLine != "") {
                Console.Write(indexHex);
                dataAscii += "\n";
                Console.Write(dataHexLine.PadRight(49, ' ') + dataAscii);
            }
        }

        private static string CreateFilter(ArgumentParser arguments) {
            var port = "";
            var filter = "";
            if (arguments.Tcp) {
                filter += "(ip or ip6 and tcp) or ";
            }
            if (arguments.Udp) {
                filter += "(ip or ip6 and udp) or ";
            }
            if (arguments.Icmp) {
                filter += "(icmp or icmp6) or ";
            }
            if (arguments.Arp) {
                filter += "(arp) or ";
            }
            if (arguments.Port != null) {
                port = $"(port {arguments.Port})";
            }
            if (port == "" && filter == "") {
                filter = "(ip or ip6 and tcp) or (ip or ip6 and udp) or (icmp or icmp6) or (arp)";
            } else if (filter != "" && port != "") {
                filter = filter.Remove(filter.Length - 4, 4);
                filter = $"({filter}) and {port}";
            } else if (filter == "" && port != "") {
                filter = $"{port} and ((ip or ip6 and tcp) or (ip or ip6 and udp) or (icmp or icmp6) or (arp))";
            } else if (filter != "" && port == "") {
                filter = filter.Remove(filter.Length - 4, 4);
            }
            return filter;
        }
    }
}
