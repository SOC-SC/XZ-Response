{ 

    meta: 

        description = "Function signature detection in liblzma used by sshd indicating any potential systems compromised" 

        author = "SOC Team" 

        reference = "YaraGen-CVE-2024-3094" 

    strings: 

        $signature = { F3 0F 1E FA 55 48 89 F5 4C 89 CE 53 89 FB 81 E7 00 00 00 80 48 83 EC 28 48 89 54 24 18 48 89 4C 24 10 } 

    condition: 

        $signature 

}
