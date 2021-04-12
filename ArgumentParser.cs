using System;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.IO;

namespace ipk_sniffer
{
    public class ArgumentParser
    {
        private string _device;
        private int? _port;
        private bool _tcp;
        private bool _udp;
        private bool _arp;
        private bool _icmp;
        private int _num;


        public ArgumentParser(string[] args)
        {
            ParseArgument(args);
            Console.WriteLine($"Device:{_device}, Port:{_port}, TCP:{_tcp}, UDP:{_udp}, ARP:{_arp}, ICMP:{_icmp}, NUM:{_num}");
            if (this._device == null) {
                NetworkTools.ListDevices();
            }
            else {
                NetworkTools.SniffPacket(_device);
            }
        }

        private int ParseArgument(string[] args)
        {
            var deviceOption = new Option<string>(
                new string[] {"-i", "--interface"},
                description:
                "Interface on which packet sniffer will listen. Without optional argument prints list of interfaces")
            {
                Argument = new Argument<string>()
                {
                    Arity = ArgumentArity.ZeroOrOne
                }
            };
            var rootCommand = new RootCommand {
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
            rootCommand.Handler = CommandHandler.Create<string, int?, bool, bool, bool, bool, int, IConsole>(this.SaveValues);
            return rootCommand.InvokeAsync(args).Result;
        }
        
        private void SaveValues(string @interface, int? port, bool tcp, bool udp, bool arp, bool icmp, int n, IConsole console) {
            
            if ((port >= 1 && port <= 65535) || port == null) {
                this._port = port;
            }
            else {
                Console.WriteLine("Uh on");
                Environment.Exit((int) ReturnCode.ErrArguments);
            }
            this._device = @interface;
            this._tcp = tcp;
            this._udp = udp;
            this._arp = arp;
            this._icmp = icmp;
            this._num = n;
        }
        
    }
}