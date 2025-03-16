//! FSCTL codes and structs.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FsctlCodes {
    DfsGetReferrals = 0x00060194,
    PipePeek = 0x0011400C,
    PipeWait = 0x00110018,
    PipeTransceive = 0x0011C017,
    SrvCopychunk = 0x001440F2,
    SrvEnumerateSnapshots = 0x00144064,
    SrvRequestResumeKey = 0x00140078,
    SrvReadHash = 0x001441bb,
    SrvCopychunkWrite = 0x001480F2,
    LmrRequestResiliency = 0x001401D4,
    QueryNetworkInterfaceInfo = 0x001401FC,
    SetReparsePoint = 0x000900A4,
    DfsGetReferralsEx = 0x000601B0,
    FileLevelTrim = 0x00098208,
    ValidateNegotiateInfo = 0x00140204,
}
