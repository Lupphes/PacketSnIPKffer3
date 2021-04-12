using System;

namespace ipk_sniffer
{
    [Flags]
    public enum ReturnCode : int
    {
        Success = 0,
        ErrArguments = 1
    }
}