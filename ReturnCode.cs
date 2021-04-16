using System;

namespace ipk_sniffer
{
    /// <summary>
    /// Describe all return codes of the application
    /// </summary>
    [Flags]
    public enum ReturnCode : int
    {
        ///<summary>Application ended successfully</summary>
        Success = 0,
        ///<summary>Error while parsing the arguments</summary>
        ErrArguments = 1,
        ///<summary>User-specified invalid port</summary>
        ErrInvalidPort = 2,
        ///<summary>User-specified invalid parameters for the filter.
        /// ARP and ICMP can't be combined with port.</summary>
        ErrInvalidFilter = 3,
        ///<summary>Error in SharpPcap library</summary>
        ErrPCap = 4,
        ///<summary>General error. Sorry</summary>
        ErrGeneralCapture = 5
    }
}
