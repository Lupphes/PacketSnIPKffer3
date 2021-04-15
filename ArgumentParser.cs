using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Invocation;

namespace ipk_sniffer
{
    public class ArgumentParser
    {
        internal string Device;
        internal int? Port;
        internal bool Tcp;
        internal bool Udp;
        internal bool Arp;
        internal bool Icmp;
        internal int Num;
        private Dictionary<string, Dictionary<string, string>> _devicesDict;


        public ArgumentParser(string[] args)
        {
            ParseArgument(args);
            Console.WriteLine(
                $"Device:{Device}, Port:{Port}, TCP:{Tcp}, UDP:{Udp}, ARP:{Arp}, ICMP:{Icmp}, NUM:{Num}");
            if (this.Device == null)
            {
                _devicesDict = NetworkTools.ListDevices();
                this.WriteDevices();
                Environment.Exit((int) ReturnCode.Success);
            }
        }

        private void ParseArgument(string[] args)
        {
            var deviceOption = new Option<string>(
                new string[] {"--interface", "-i"},
                description:
                "Interface on which packet sniffer will listen. Without optional argument prints list of interfaces")
            {
                Argument = new Argument<string>()
                {
                    Arity = ArgumentArity.ZeroOrOne
                }
            };
            var rootCommand = new RootCommand
            {
                deviceOption,
                new Option<int?>(
                    new string[] {"--port", "-p"},
                    description: "Specified listening port. If not specified, listen on all"),
                new Option(
                    new string[] {"--tcp", "-t"},
                    description: "Display TCP packets"),
                new Option(
                    new string[] {"--udp", "-u"},
                    description:
                    "Display UDP packets"),
                new Option(
                    "--arp",
                    description:
                    "Display only ICMPv4 and ICMPv6 packets"),
                new Option(
                    "--icmp",
                    description:
                    "Display ARP frames"),
                new Option<int>(
                    "-n",
                    getDefaultValue: () => 1,
                    description:
                    "Number of packets")
            };
            rootCommand.Description = "IPK Project 2: Zeta -- xsloup02";
            rootCommand.Name = "ipk-sniffer";

            rootCommand.Handler =
                CommandHandler.Create<string, int?, bool, bool, bool, bool, int, IConsole>(this.SaveValues);
            if (rootCommand.InvokeAsync(args).Result != 0) {
                Environment.Exit((int)ReturnCode.ErrArguments);
            }
        }

        private void SaveValues(string @interface, int? port, bool tcp, bool udp, bool arp, bool icmp, int n,
            IConsole console)
        {

            if ((port >= 1 && port <= 65535) || port == null) {
                this.Port = port;
            }
            else
            {
                Console.WriteLine("Specified port is not valid. It needs to be greater than 0 and lower than 65535");
                Environment.Exit((int) ReturnCode.ErrInvalidPort);
            }
            if ((arp || icmp) && port != null)
            {
                Console.WriteLine("Port cannot be combined with ARP or ICMP argument");
                Environment.Exit((int)ReturnCode.ErrInvalidFilter);
            }

            this.Device = @interface;
            this.Tcp = tcp;
            this.Udp = udp;
            this.Arp = arp;
            this.Icmp = icmp;
            this.Num = n;
        }

        public void WriteDevices()
        {
            Console.WriteLine("List of all interfaces:");
            
            foreach (KeyValuePair<string, Dictionary<string, string>> device in this._devicesDict)
            {
                string deviceString = "";
                if (device.Value["happyName"] != null)
                {
                    deviceString += $"{device.Value["happyName"]} ({device.Key}):\n";
                }
                else
                {
                    deviceString += $"{device.Key}:\n";
                }
                if (device.Value["mac"] != null)
                {
                    deviceString += "\tMAC: ";
                    deviceString += $"{device.Value["mac"]}\n\t";
                }
                if (device.Value["address"] != null)
                {
                    deviceString += "IP:";
                    deviceString += $"{device.Value["address"]}";
                    deviceString += "\n";
                }
                if (device.Value["description"] != "")
                {
                    deviceString += $"\tDescription: {device.Value["description"]}";
                }

                Console.WriteLine(deviceString);
            }
        }
    }
}
