using System;


namespace ipk_sniffer
{
    static class Program
    {
        private static void Main(string[] args)
        {
            var arguments = new ArgumentParser(args);
            NetworkTools.SniffPacket(arguments);
        }
    }
}   