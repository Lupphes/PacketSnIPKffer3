using System;

namespace ipk_sniffer
{
    [Flags]
    public enum ReturnCode : int
    {
        Success = 0,
        ErrArguments = 1,
        ErrInvalidPort = 2,
        ErrInvalidFilter = 3,
        ErrPCap = 4,
        ErrGeneralCapture = 5
    }
}