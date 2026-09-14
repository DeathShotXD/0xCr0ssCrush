/*
   YARA rules for the DCRCVDrv.sys and Alinubx.sys samples used by the
   Cruciferra loader (eSentire TRU, 2026-08-19).

   Detection is hash-first (import-agnostic) with an optional PE
   metadata marker rule for renamed copies.
*/

import "pe"

rule cruciferra_dcrcvdrv_sha256 {
    meta:
        author = "0xCr0ssCrush research"
        description = "DCRCVDrv.sys (MocoMsys) sample used by the Cruciferra loader"
        date = "2026-09-10"
        reference = "https://www.esentire.com/blog/malware-as-a-service-cocktail-errtraffic-and-cruciferra-killing-your-edr-since-2025"
        hash_sha256 = "87e8d39db624f37d3e77aedf487a2dfd197f71a4730ea74f4e7a4341deaec2ff"
        hash_sha1 = "47d922b0fd5d704025d14ef98ded46e74830a423"
        hash_md5 = "567c158ee0858f8e941d4ab7a6c18dbc"
    condition:
        filesize == 141240 and pe.machine == pe.MACHINE_AMD64 and
        hash.sha256(0, filesize) == "87e8d39db624f37d3e77aedf487a2dfd197f71a4730ea74f4e7a4341deaec2ff"
}

rule cruciferra_alinubx_sha256 {
    meta:
        author = "0xCr0ssCrush research"
        description = "Alinubx.sys (CnCrypt) sample associated with the Cruciferra loader"
        date = "2026-09-10"
        reference = "https://www.esentire.com/blog/malware-as-a-service-cocktail-errtraffic-and-cruciferra-killing-your-edr-since-2025"
        hash_sha256 = "611b3ba687b7f46319a19609605ddfe5225e6d85277d8e923eea3fdb6f7b5b61"
        hash_sha1 = "172c5ce3afab6d63fe12a7e036f20271b9d09c13"
        hash_md5 = "10b3049f4a954665512eca5d24728c89"
    condition:
        filesize == 538664 and pe.machine == pe.MACHINE_AMD64 and
        hash.sha256(0, filesize) == "611b3ba687b7f46319a19609605ddfe5225e6d85277d8e923eea3fdb6f7b5b61"
}

rule cruciferra_driver_pecopy {
    meta:
        author = "0xCr0ssCrush research"
        description = "PE metadata markers for renamed copies of the two drivers"
        date = "2026-09-10"
    condition:
        pe.machine == pe.MACHINE_AMD64 and
        (pe.company_name contains "MOCOMSYS" or
         pe.company_name contains "CnCrypt")
}