namespace ipk_sniffer
{
    /// <summary>
    ///  The main file of a packet sniffer. 
    ///  Start parser and network tools
    /// </summary>
    static class SnifferProgram
    {
        private static void Main(string[] args)
        {
            var arguments = new ArgumentParser(args);
            NetworkTools.SniffPacket(arguments);
        }
    }
}   
