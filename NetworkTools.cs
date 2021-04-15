using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace ipk_sniffer
{
    public class NetworkTools
    {

        private static int _captured = 0;
        private static int neededToCapture = 0;
        private static ICaptureDevice _device;

        public static Dictionary<string, Dictionary<string, string>> ListDevices()
        {
            Dictionary<string, Dictionary<string, string>> devicesDict = new Dictionary<string, Dictionary<string, string>>();

            var devices = CaptureDeviceList.Instance;
            if(devices.Count < 1) { return null; }

            foreach (var device in devices.OfType<LibPcapLiveDevice>())
            {
                devicesDict[device.Name] = new Dictionary<string, string>()
                {
                    {"happyName", device.Interface.FriendlyName},
                    {"mac", device.Interface.MacAddress?.ToString()},
                    {"description", device.Interface.Description}
                    
                };
                if (device.Addresses.Count != 0)
                {
                    string tempAddress = "";
                    foreach (var deviceInterface in device.Interface.Addresses)
                    {
                        tempAddress += "\n\t   " + deviceInterface.Addr;
                    }
                    devicesDict[device.Name].Add(
                        "address", tempAddress
                    );
                }
                else
                {
                    devicesDict[device.Name].Add(
                        "address", null
                    );
                }
            }
            return devicesDict;
        }

        public static void SniffPacket(ArgumentParser arguments)
        {
            ICaptureDevice device = GetDeviceInfo(arguments.Device);
            _device = device;
            neededToCapture = arguments.Num;
            if (device == null)
            {
                Console.WriteLine("Specified device not found");
                Environment.Exit((int) ReturnCode.ErrArguments);
            }

            const int readTimeoutMilliseconds = 1000;
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);
            
            Console.WriteLine();
            Console.WriteLine("-- Listening on {0}...", device.Name);
            device.OnPacketArrival += device_OnPacketArrival;

            string filter = "ip or ip6 and tcp or ip or ip6 and udp  or icmp or icmp6";
            device.Filter = filter;

            device.StartCapture();
        }
        
        private static ICaptureDevice GetDeviceInfo(string specifiedDevice)
        {
            var devices = CaptureDeviceList.Instance;
            if (devices.Count < 1) { return null; }

            foreach (var device in devices.OfType<LibPcapLiveDevice>())
            {
                if ((device.Name.Equals(specifiedDevice) || device.Interface.FriendlyName != null && device.Interface.FriendlyName.Equals(specifiedDevice)))
                {
                    return device;
                }
            }
            return null;
        }

        private static void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            var packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var time = e.Packet.Timeval.Date.ToString("yyyy-MM-ddTHH\\:mm\\:ss.fffffffzzz");
            var len = e.Packet.Data.Length;

            var tcpPacket = packet.Extract<TcpPacket>();
            var udpPacket = packet.Extract<UdpPacket>();
            var icmpV4 = packet.Extract<IcmpV4Packet>();
            var icmpV6 = packet.Extract<IcmpV6Packet>();
            
            //ARP aRP = packet.Extract<ARP>();
            if (tcpPacket != null)
            {
                var ipPacket = (IPPacket)tcpPacket.ParentPacket;
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                int srcPort = tcpPacket.SourcePort;
                int dstPort = tcpPacket.DestinationPort;

                Console.WriteLine($"TCP {time}: {srcIp} {srcPort} > {dstIp} {dstPort}, length {len} bytes");
            } else if (udpPacket != null)
            {
                var ipPacket = (IPPacket)udpPacket.ParentPacket;
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                int srcPort = udpPacket.SourcePort;
                int dstPort = udpPacket.DestinationPort;
                Console.WriteLine($"UDP {time}: {srcIp} {srcPort} > {dstIp} {dstPort}, length {len} bytes");
            } else if (icmpV4 != null || icmpV6 != null)
            {
                if (icmpV4 != null)
                {
                    var ipPacket = (IPPacket)icmpV4.ParentPacket;
                    System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                    System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                    Console.WriteLine($"ICMP4 {time}: {srcIp} > {dstIp}, length {len} bytes");
                }
                else
                {
                    var ipPacket = (IPPacket)icmpV6.ParentPacket;
                    System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                    System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                    Console.WriteLine($"ICMP6 {time}: {srcIp} > {dstIp}, length {len} bytes");
                }
            }

            string dataHexLine = "";
            string dataAscii = "";
            string indexHex = "";
            for (int i = 1; i < packet.BytesSegment.Bytes.Length+1; i++)
            {
                dataHexLine += packet.BytesSegment.Bytes[i - 1].ToString("x").PadLeft(2, '0') + " ";
                dataAscii += (packet.BytesSegment.Bytes[i - 1] >= 33 && packet.BytesSegment.Bytes[i - 1] <= 126)
                    ? Encoding.ASCII.GetString(new byte[] {packet.BytesSegment.Bytes[i - 1]})
                    : ".";
                
                if (i % 16 == 0)
                {
                    indexHex = $"0x{i:X4}: ";
                    Console.Write($"0x{i-1:X4}: ");
                    dataAscii += "\n";
                    Console.Write(dataHexLine + dataAscii);
                    dataHexLine = "";
                    dataAscii = "";
                }
                else if (i % 8 == 0)
                {
                    dataHexLine += " ";
                    dataAscii += " ";
                }
            }

            if (dataHexLine != "")
            {
                Console.Write(indexHex);
                dataAscii += "\n";
                Console.Write(dataHexLine.PadRight(49, ' ') + dataAscii);
                dataHexLine = "";
                dataAscii = "";
                
            }



            _captured++;
            if (_captured == neededToCapture)
            {
                _device.StopCapture();
            }
        }
    }
}