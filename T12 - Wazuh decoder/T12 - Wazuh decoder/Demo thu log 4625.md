# Các channel đang cho wazuh thu:
- Microsoft-Windows-PowerShell/Operational
- Microsoft-Windows-Windows Defender/Operational
- Microsoft-Windows-TaskScheduler/Operational
- Microsoft-Windows-Sysmon/Operational
- Application
- Security (Config hiện tại đang **lọc bỏ** 13 EventID noise: 5145, 5156, 5447, 4656, 4658, 4663, 4660, 4670, 4690,  4703, 4907, 5152, 5157)
- System

**Quy trình đúng:**

```
Agent gửi log → Analysisd (server) xử lý trực tiếp
                    ├── decode + rule match
                    ├── nếu level > 2 → ghi vào alerts.json
                    └── nếu logall=yes → ghi vào archives.json
```

Analysisd xử lý log **trực tiếp trong memory**, không phải đọc từ archives rồi mới đối chiếu rule. Archives và alerts là hai đầu ra song song, không phải tuần tự.
## /var/ossec/logs/alerts/alerts.json

```json
{
   "timestamp":"2026-04-08T14:34:22.745+0700",
   "rule":{
      "level":5,
      "description":"Logon Failure - Unknown user or bad password",
      "id":"60122",
      "mitre":{
         "id":[
            "T1531"
         ],
         "tactic":[
            "Impact"
         ],
         "technique":[
            "Account Access Removal"
         ]
      },
      "firedtimes":1,
      "mail":false,
      "groups":[
         "windows",
         "windows_security",
         "authentication_failed"
      ],
      "pci_dss":[
         "10.2.4",
         "10.2.5"
      ],
      "gpg13":[
         "7.1"
      ],
      "gdpr":[
         "IV_35.7.d",
         "IV_32.2"
      ],
      "hipaa":[
         "164.312.b"
      ],
      "nist_800_53":[
         "AU.14",
         "AC.7"
      ],
      "tsc":[
         "CC6.1",
         "CC6.8",
         "CC7.2",
         "CC7.3"
      ]
   },
   "agent":{
      "id":"001",
      "name":"client1",
      "ip":"192.168.10.130"
   },
   "manager":{
      "name":"wazuh"
   },
   "id":"1775633662.884372",
   "decoder":{
      "name":"windows_eventchannel"
   },
   "data":{
      "win":{
         "system":{
            "providerName":"Microsoft-Windows-Security-Auditing",
            "providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}",
            "eventID":"4625",
            "version":"0",
            "level":"0",
            "task":"12544",
            "opcode":"0",
            "keywords":"0x8010000000000000",
            "systemTime":"2026-04-08T07:34:31.2723240Z",
            "eventRecordID":"28374",
            "processID":"832",
            "threadID":"10016",
            "channel":"Security",
            "computer":"client1",
            "severityValue":"AUDIT_FAILURE",
            "message":"\"An account failed to log on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tCLIENT1$\r\n\tAccount Domain:\t\tWORKGROUP\r\n\tLogon ID:\t\t0x3E7\r\n\r\nLogon Type:\t\t\t2\r\n\r\nAccount For Which Logon Failed:\r\n\tSecurity ID:\t\tS-1-0-0\r\n\tAccount Name:\t\tViAnh\r\n\tAccount Domain:\t\tCLIENT1\r\n\r\nFailure Information:\r\n\tFailure Reason:\t\tUnknown user name or bad password.\r\n\tStatus:\t\t\t0xC000006D\r\n\tSub Status:\t\t0xC000006A\r\n\r\nProcess Information:\r\n\tCaller Process ID:\t0x670\r\n\tCaller Process Name:\tC:\\Windows\\System32\\svchost.exe\r\n\r\nNetwork Information:\r\n\tWorkstation Name:\tCLIENT1\r\n\tSource Network Address:\t127.0.0.1\r\n\tSource Port:\t\t0\r\n\r\nDetailed Authentication Information:\r\n\tLogon Process:\t\tUser32 \r\n\tAuthentication Package:\tNegotiate\r\n\tTransited Services:\t-\r\n\tPackage Name (NTLM only):\t-\r\n\tKey Length:\t\t0\r\n\r\nThis event is generated when a logon request fails. It is generated on the computer where access was attempted.\r\n\r\nThe Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\r\n\r\nThe Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).\r\n\r\nThe Process Information fields indicate which account and process on the system requested the logon.\r\n\r\nThe Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\r\n\r\nThe authentication information fields provide detailed information about this specific logon request.\r\n\t- Transited services indicate which intermediate services have participated in this logon request.\r\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.\""
         },
         "eventdata":{
            "subjectUserSid":"S-1-5-18",
            "subjectUserName":"CLIENT1$",
            "subjectDomainName":"WORKGROUP",
            "subjectLogonId":"0x3e7",
            "targetUserSid":"S-1-0-0",
            "targetUserName":"ViAnh",
            "targetDomainName":"CLIENT1",
            "status":"0xc000006d",
            "failureReason":"%%2313",
            "subStatus":"0xc000006a",
            "logonType":"2",
            "logonProcessName":"User32",
            "authenticationPackageName":"Negotiate",
            "workstationName":"CLIENT1",
            "keyLength":"0",
            "processId":"0x670",
            "processName":"C:\\\\Windows\\\\System32\\\\svchost.exe",
            "ipAddress":"127.0.0.1",
            "ipPort":"0"
         }
      }
   },
   "location":"EventChannel"
}
```

## /var/ossec/logs/archives/archives.json

```json
{
   "timestamp":"2026-04-08T14:34:22.745+0700",
   "rule":{
      "level":5,
      "description":"Logon Failure - Unknown user or bad password",
      "id":"60122",
      "mitre":{
         "id":[
            "T1531"
         ],
         "tactic":[
            "Impact"
         ],
         "technique":[
            "Account Access Removal"
         ]
      },
      "firedtimes":1,
      "mail":false,
      "groups":[
         "windows",
         "windows_security",
         "authentication_failed"
      ],
      "pci_dss":[
         "10.2.4",
         "10.2.5"
      ],
      "gpg13":[
         "7.1"
      ],
      "gdpr":[
         "IV_35.7.d",
         "IV_32.2"
      ],
      "hipaa":[
         "164.312.b"
      ],
      "nist_800_53":[
         "AU.14",
         "AC.7"
      ],
      "tsc":[
         "CC6.1",
         "CC6.8",
         "CC7.2",
         "CC7.3"
      ]
   },
   "agent":{
      "id":"001",
      "name":"client1",
      "ip":"192.168.10.130"
   },
   "manager":{
      "name":"wazuh"
   },
   "id":"1775633662.884372",
   "full_log":"{\"win\":{\"system\":{\"providerName\":\"Microsoft-Windows-Security-Auditing\",\"providerGuid\":\"{54849625-5478-4994-a5ba-3e3b0328c30d}\",\"eventID\":\"4625\",\"version\":\"0\",\"level\":\"0\",\"task\":\"12544\",\"opcode\":\"0\",\"keywords\":\"0x8010000000000000\",\"systemTime\":\"2026-04-08T07:34:31.2723240Z\",\"eventRecordID\":\"28374\",\"processID\":\"832\",\"threadID\":\"10016\",\"channel\":\"Security\",\"computer\":\"client1\",\"severityValue\":\"AUDIT_FAILURE\",\"message\":\"\\\"An account failed to log on.\\r\\n\\r\\nSubject:\\r\\n\\tSecurity ID:\\t\\tS-1-5-18\\r\\n\\tAccount Name:\\t\\tCLIENT1$\\r\\n\\tAccount Domain:\\t\\tWORKGROUP\\r\\n\\tLogon ID:\\t\\t0x3E7\\r\\n\\r\\nLogon Type:\\t\\t\\t2\\r\\n\\r\\nAccount For Which Logon Failed:\\r\\n\\tSecurity ID:\\t\\tS-1-0-0\\r\\n\\tAccount Name:\\t\\tViAnh\\r\\n\\tAccount Domain:\\t\\tCLIENT1\\r\\n\\r\\nFailure Information:\\r\\n\\tFailure Reason:\\t\\tUnknown user name or bad password.\\r\\n\\tStatus:\\t\\t\\t0xC000006D\\r\\n\\tSub Status:\\t\\t0xC000006A\\r\\n\\r\\nProcess Information:\\r\\n\\tCaller Process ID:\\t0x670\\r\\n\\tCaller Process Name:\\tC:\\\\Windows\\\\System32\\\\svchost.exe\\r\\n\\r\\nNetwork Information:\\r\\n\\tWorkstation Name:\\tCLIENT1\\r\\n\\tSource Network Address:\\t127.0.0.1\\r\\n\\tSource Port:\\t\\t0\\r\\n\\r\\nDetailed Authentication Information:\\r\\n\\tLogon Process:\\t\\tUser32 \\r\\n\\tAuthentication Package:\\tNegotiate\\r\\n\\tTransited Services:\\t-\\r\\n\\tPackage Name (NTLM only):\\t-\\r\\n\\tKey Length:\\t\\t0\\r\\n\\r\\nThis event is generated when a logon request fails. It is generated on the computer where access was attempted.\\r\\n\\r\\nThe Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\\r\\n\\r\\nThe Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).\\r\\n\\r\\nThe Process Information fields indicate which account and process on the system requested the logon.\\r\\n\\r\\nThe Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\\r\\n\\r\\nThe authentication information fields provide detailed information about this specific logon request.\\r\\n\\t- Transited services indicate which intermediate services have participated in this logon request.\\r\\n\\t- Package name indicates which sub-protocol was used among the NTLM protocols.\\r\\n\\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.\\\"\"},\"eventdata\":{\"subjectUserSid\":\"S-1-5-18\",\"subjectUserName\":\"CLIENT1$\",\"subjectDomainName\":\"WORKGROUP\",\"subjectLogonId\":\"0x3e7\",\"targetUserSid\":\"S-1-0-0\",\"targetUserName\":\"ViAnh\",\"targetDomainName\":\"CLIENT1\",\"status\":\"0xc000006d\",\"failureReason\":\"%%2313\",\"subStatus\":\"0xc000006a\",\"logonType\":\"2\",\"logonProcessName\":\"User32\",\"authenticationPackageName\":\"Negotiate\",\"workstationName\":\"CLIENT1\",\"keyLength\":\"0\",\"processId\":\"0x670\",\"processName\":\"C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\svchost.exe\",\"ipAddress\":\"127.0.0.1\",\"ipPort\":\"0\"}}}",
   "decoder":{
      "name":"windows_eventchannel"
   },
   "data":{
      "win":{
         "system":{
            "providerName":"Microsoft-Windows-Security-Auditing",
            "providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}",
            "eventID":"4625",
            "version":"0",
            "level":"0",
            "task":"12544",
            "opcode":"0",
            "keywords":"0x8010000000000000",
            "systemTime":"2026-04-08T07:34:31.2723240Z",
            "eventRecordID":"28374",
            "processID":"832",
            "threadID":"10016",
            "channel":"Security",
            "computer":"client1",
            "severityValue":"AUDIT_FAILURE",
            "message":"\"An account failed to log on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tCLIENT1$\r\n\tAccount Domain:\t\tWORKGROUP\r\n\tLogon ID:\t\t0x3E7\r\n\r\nLogon Type:\t\t\t2\r\n\r\nAccount For Which Logon Failed:\r\n\tSecurity ID:\t\tS-1-0-0\r\n\tAccount Name:\t\tViAnh\r\n\tAccount Domain:\t\tCLIENT1\r\n\r\nFailure Information:\r\n\tFailure Reason:\t\tUnknown user name or bad password.\r\n\tStatus:\t\t\t0xC000006D\r\n\tSub Status:\t\t0xC000006A\r\n\r\nProcess Information:\r\n\tCaller Process ID:\t0x670\r\n\tCaller Process Name:\tC:\\Windows\\System32\\svchost.exe\r\n\r\nNetwork Information:\r\n\tWorkstation Name:\tCLIENT1\r\n\tSource Network Address:\t127.0.0.1\r\n\tSource Port:\t\t0\r\n\r\nDetailed Authentication Information:\r\n\tLogon Process:\t\tUser32 \r\n\tAuthentication Package:\tNegotiate\r\n\tTransited Services:\t-\r\n\tPackage Name (NTLM only):\t-\r\n\tKey Length:\t\t0\r\n\r\nThis event is generated when a logon request fails. It is generated on the computer where access was attempted.\r\n\r\nThe Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\r\n\r\nThe Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).\r\n\r\nThe Process Information fields indicate which account and process on the system requested the logon.\r\n\r\nThe Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\r\n\r\nThe authentication information fields provide detailed information about this specific logon request.\r\n\t- Transited services indicate which intermediate services have participated in this logon request.\r\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.\""
         },
         "eventdata":{
            "subjectUserSid":"S-1-5-18",
            "subjectUserName":"CLIENT1$",
            "subjectDomainName":"WORKGROUP",
            "subjectLogonId":"0x3e7",
            "targetUserSid":"S-1-0-0",
            "targetUserName":"ViAnh",
            "targetDomainName":"CLIENT1",
            "status":"0xc000006d",
            "failureReason":"%%2313",
            "subStatus":"0xc000006a",
            "logonType":"2",
            "logonProcessName":"User32",
            "authenticationPackageName":"Negotiate",
            "workstationName":"CLIENT1",
            "keyLength":"0",
            "processId":"0x670",
            "processName":"C:\\\\Windows\\\\System32\\\\svchost.exe",
            "ipAddress":"127.0.0.1",
            "ipPort":"0"
         }
      }
   },
   "location":"EventChannel"
}
```

**archives.json và alerts.json chứa cùng một record** — cùng `id: "1775633662.884372"`, cùng timestamp. Nghĩa là Wazuh không lưu riêng "tất cả log" vào archives — nó chỉ copy alert đã có rule match vào đó.

Sự khác biệt duy nhất giữa hai file là archives có thêm field `full_log` — chứa raw JSON nguyên gốc agent gửi lên, trước khi decode.


