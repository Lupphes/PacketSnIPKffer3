using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Invocation;

namespace ipk_sniffer
{
    /// <summary>
    ///  Parse given arguments, validate them and save them
    ///  Also print the list of devices if only interface is given
    /// </summary>
    public class ArgumentParser
    {
        internal string Device; // Interface
        internal int? Port;
        internal bool Tcp;
        internal bool Udp;
        internal bool Arp;
        internal bool Icmp;
        internal int Num;
        private readonly Dictionary<string, Dictionary<string, string>> _devicesDict;

        /// <summary>
        ///  Launch parser
        ///  Print the list of devices if only interface is given
        /// </summary>
        public ArgumentParser(string[] args)
        {
            ParseArgument(args);
            // This line is here for debugging purposes. Lets you see what arguments were given
            //Console.WriteLine(
            //    $"Device: {Device}, Port: {Port}, TCP: {Tcp}, UDP: {Udp}, ARP: {Arp}, ICMP: {Icmp}, NUM: {Num}"
            foreach (var item in args) {
                if (item.Equals("-?") | item.Equals("-h") || item.Equals("--help") || item.Equals("--version")) {
                    Environment.Exit((int)ReturnCode.Success);
                }
            }
            if (this.Device == null) {
                _devicesDict = NetworkTools.ListDevices();
                this.WriteDevices();
                Environment.Exit((int) ReturnCode.Success);
            }
        }

        /// <summary>
        ///  Parse the arguments and calls the handler to save them.
        ///  Exits the application If there was an error
        /// </summary>
        private void ParseArgument(string[] args)
        {
            var deviceOption = new Option<string>(
                new[] {"--interface", "-i"},
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
                    new[] {"--port", "-p"},
                    description: "Specified listening port. If not specified, listen on all"),
                new Option(
                    new[] {"--tcp", "-t"},
                    description: "Display TCP packets"),
                new Option(
                    new[] {"--udp", "-u"},
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

        /// <summary>
        ///  Validate the data and save them into the instance
        /// </summary>
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
            if ((arp || icmp) && port != null) {
                if (Udp || tcp) {
                    Console.WriteLine("Warning: Filtering using ARP or ICMP with port is not possible.");
                    arp = false;
                    icmp = false;
                } else {
                    Console.WriteLine("Port specification cannot be combined with ARP or ICMP argument");
                    Environment.Exit((int)ReturnCode.ErrInvalidFilter);
                }
            }

            this.Device = @interface;
            this.Tcp = tcp;
            this.Udp = udp;
            this.Arp = arp;
            this.Icmp = icmp;
            this.Num = n;
        }

        /// <summary>
        ///  Print the devices with their information into the console
        /// </summary>
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
