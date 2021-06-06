#pragma once
union PTE {
    unsigned __int64 All;
    struct {
        unsigned __int64 Read : 1; // bit 0											 
        unsigned __int64 Write : 1; // bit 1										 
        unsigned __int64 Execute : 1; // bit 2
        unsigned __int64 EPTMemoryType : 3; // bit 5:3 (EPT Memory type)
        unsigned __int64 IgnorePAT : 1; // bit 6
        unsigned __int64 Ignored1 : 1; // bit 7
        unsigned __int64 AccessedFlag : 1; // bit 8	
        unsigned __int64 DirtyFlag : 1; // bit 9
        unsigned __int64 ExecuteForUserMode : 1; // bit 10
        unsigned __int64 Ignored2 : 1; // bit 11
        unsigned __int64 PhysicalAddress : 36; // bit (N-1):12 or Page-Frame-Number
        unsigned __int64 Reserved : 4; // bit 51:N
        unsigned __int64 Ignored3 : 11; // bit 62:52
        unsigned __int64 SuppressVE : 1; // bit 63
    }Fields;
};