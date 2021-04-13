using System;
using System.Linq;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace ipk_sniffer
{
    public class NetworkTools
    {
        public static ICaptureDevice ListDevices()
        {
            
            var devices = CaptureDeviceList.Instance;
            if(devices.Count < 1) { return null; }

            foreach (var dev in devices.OfType<LibPcapLiveDevice>()) {
                foreach (var add in dev.Interface.Addresses)
                {
                    Console.WriteLine("");
                    Console.WriteLine(add.Addr.hardwareAddress);
                }
                
                
                if (dev.Addresses.Count == 0)
                {
                        
                }
            }
            return null;
        }

        public static void SniffPacket(string inter)
        {
            // Extract a device from the list
            var devices = CaptureDeviceList.Instance;/*
            ICaptureDevice device = GetDeviceInfo(inter);*/
            /*if (device == null)
            {
                Console.WriteLine("Smula");
                Environment.Exit((int) ReturnCode.ErrArguments);
            }*/
            void Device_OnPacketArrival(object s, CaptureEventArgs e)
            {
                Console.WriteLine(e.Packet);
            }

            var device = LibPcapLiveDeviceList.Instance[0];
            device.Open();
            device.OnPacketArrival += Device_OnPacketArrival;

            Console.WriteLine("-- Listening on {0}, hit 'Enter' to stop...",
                device.Description);

            // Start the capturing process
            device.StartCapture();

            // Wait for 'Enter' from the user.
            Console.ReadLine();

            // Stop the capturing process
            device.StopCapture();

            // Close the pcap device
            device.Close();
        }
        
        private static void device_OnPacketArrival(object sender, CaptureEventArgs packet)
        {
            DateTime time = packet.Packet.Timeval.Date;
            int len = packet.Packet.Data.Length;
            Console.WriteLine("{0}:{1}:{2},{3} Len={4}",
                time.Hour, time.Minute, time.Second, time.Millisecond, len);
        }

        private void Device_OnPacketArrival(object s, CaptureEventArgs e)
        {
            Console.WriteLine(e.Packet);
        }

        private static ICaptureDevice GetDeviceInfo(string device)
        {
            return null;
        }

        public static void WriteDevices()
        {
        }
    }
}