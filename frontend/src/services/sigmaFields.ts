/**
 * SIGMA Field Reference Service
 *
 * Provides comprehensive SIGMA standard field definitions organized by category.
 * This service is used for autocomplete, validation, and field documentation
 * throughout the rule builder UI.
 */

export type SigmaFieldCategory =
  | 'process_creation'
  | 'network_connection'
  | 'file_event'
  | 'registry_event'
  | 'dns_query'
  | 'authentication'
  | 'image_load'
  | 'service_creation'
  | 'powershell'
  | 'firewall'
  | 'web_proxy'
  | 'cloud_aws'
  | 'cloud_azure'
  | 'cloud_gcp'
  | 'system'
  | 'generic';

export type SigmaFieldDataType = 'string' | 'number' | 'boolean' | 'array' | 'timestamp';

export type SigmaLogSource =
  | 'windows_sysmon'
  | 'windows_security'
  | 'windows_powershell'
  | 'linux_auditd'
  | 'linux_syslog'
  | 'aws_cloudtrail'
  | 'azure_activity'
  | 'gcp_audit'
  | 'web_proxy'
  | 'firewall'
  | 'dns'
  | 'generic';

export interface SigmaField {
  /** SIGMA standard field name (PascalCase) */
  name: string;

  /** Field category for grouping */
  category: SigmaFieldCategory;

  /** Human-readable description */
  description: string;

  /** Example query using this field */
  example: string;

  /** Log sources that typically contain this field */
  logSources: SigmaLogSource[];

  /** Field data type */
  dataType: SigmaFieldDataType;

  /** Common values for this field (used for autocomplete) */
  commonValues?: string[];

  /** Legacy field names that map to this SIGMA field */
  aliases?: string[];
}

/**
 * Comprehensive SIGMA field definitions
 * Based on SIGMA specification and Cerberus field_aliases.go
 */
export const SIGMA_FIELDS: SigmaField[] = [
  // ==================== PROCESS CREATION FIELDS ====================
  {
    name: 'Image',
    category: 'process_creation',
    description: 'Process executable path',
    example: 'Image = "C:\\\\Windows\\\\System32\\\\cmd.exe"',
    logSources: ['windows_sysmon', 'windows_security', 'linux_auditd'],
    dataType: 'string',
    commonValues: ['powershell.exe', 'cmd.exe', 'rundll32.exe', 'wscript.exe', 'cscript.exe'],
    aliases: ['image', 'process_name', 'process']
  },
  {
    name: 'CommandLine',
    category: 'process_creation',
    description: 'Process command line arguments',
    example: 'CommandLine contains "whoami"',
    logSources: ['windows_sysmon', 'windows_security', 'linux_auditd'],
    dataType: 'string',
    aliases: ['command_line', 'commandline', 'command', 'cmd']
  },
  {
    name: 'ParentImage',
    category: 'process_creation',
    description: 'Parent process executable path',
    example: 'ParentImage = "C:\\\\Windows\\\\explorer.exe"',
    logSources: ['windows_sysmon', 'windows_security', 'linux_auditd'],
    dataType: 'string',
    commonValues: ['explorer.exe', 'services.exe', 'svchost.exe'],
    aliases: ['parent_image', 'parent_process_name', 'parent_process']
  },
  {
    name: 'ParentCommandLine',
    category: 'process_creation',
    description: 'Parent process command line',
    example: 'ParentCommandLine contains "powershell"',
    logSources: ['windows_sysmon', 'windows_security'],
    dataType: 'string',
    aliases: ['parent_command_line', 'parent_commandline']
  },
  {
    name: 'ProcessId',
    category: 'process_creation',
    description: 'Process identifier (PID)',
    example: 'ProcessId > 1000',
    logSources: ['windows_sysmon', 'windows_security', 'linux_auditd'],
    dataType: 'number',
    aliases: ['process_id', 'pid']
  },
  {
    name: 'ParentProcessId',
    category: 'process_creation',
    description: 'Parent process identifier (PPID)',
    example: 'ParentProcessId = 4',
    logSources: ['windows_sysmon', 'windows_security', 'linux_auditd'],
    dataType: 'number',
    aliases: ['parent_process_id', 'ppid']
  },
  {
    name: 'CurrentDirectory',
    category: 'process_creation',
    description: 'Process current working directory',
    example: 'CurrentDirectory = "C:\\\\Users\\\\Public"',
    logSources: ['windows_sysmon', 'linux_auditd'],
    dataType: 'string',
    aliases: ['current_directory', 'cwd']
  },
  {
    name: 'ProcessGuid',
    category: 'process_creation',
    description: 'Process GUID (Sysmon)',
    example: 'ProcessGuid exists',
    logSources: ['windows_sysmon'],
    dataType: 'string',
    aliases: ['process_guid']
  },
  {
    name: 'ParentProcessGuid',
    category: 'process_creation',
    description: 'Parent process GUID (Sysmon)',
    example: 'ParentProcessGuid exists',
    logSources: ['windows_sysmon'],
    dataType: 'string',
    aliases: ['parent_process_guid']
  },
  {
    name: 'IntegrityLevel',
    category: 'process_creation',
    description: 'Process integrity level',
    example: 'IntegrityLevel = "High"',
    logSources: ['windows_sysmon', 'windows_security'],
    dataType: 'string',
    commonValues: ['Low', 'Medium', 'High', 'System'],
    aliases: ['integrity_level']
  },

  // ==================== USER FIELDS ====================
  {
    name: 'User',
    category: 'process_creation',
    description: 'User account name',
    example: 'User contains "admin"',
    logSources: ['windows_sysmon', 'windows_security', 'linux_auditd'],
    dataType: 'string',
    aliases: ['user', 'username', 'user_name', 'subject_user_name']
  },
  {
    name: 'TargetUserName',
    category: 'authentication',
    description: 'Target user account name',
    example: 'TargetUserName = "Administrator"',
    logSources: ['windows_security'],
    dataType: 'string',
    aliases: ['target_user_name', 'target_user']
  },
  {
    name: 'SubjectDomainName',
    category: 'authentication',
    description: 'Subject domain name',
    example: 'SubjectDomainName = "CORP"',
    logSources: ['windows_security'],
    dataType: 'string',
    aliases: ['subject_domain_name']
  },
  {
    name: 'TargetDomainName',
    category: 'authentication',
    description: 'Target domain name',
    example: 'TargetDomainName = "CORP"',
    logSources: ['windows_security'],
    dataType: 'string',
    aliases: ['target_domain_name']
  },
  {
    name: 'LogonId',
    category: 'authentication',
    description: 'Logon session ID',
    example: 'LogonId exists',
    logSources: ['windows_security'],
    dataType: 'string',
    aliases: ['logon_id']
  },

  // ==================== NETWORK FIELDS ====================
  {
    name: 'SourceIp',
    category: 'network_connection',
    description: 'Source IP address',
    example: 'SourceIp = "192.168.1.100"',
    logSources: ['windows_sysmon', 'firewall', 'web_proxy', 'generic'],
    dataType: 'string',
    aliases: ['source_ip', 'src_ip', 'src', 'source_address']
  },
  {
    name: 'DestinationIp',
    category: 'network_connection',
    description: 'Destination IP address',
    example: 'DestinationIp = "10.0.0.1"',
    logSources: ['windows_sysmon', 'firewall', 'web_proxy', 'generic'],
    dataType: 'string',
    aliases: ['destination_ip', 'dest_ip', 'dst_ip', 'dst', 'destination_address']
  },
  {
    name: 'SourcePort',
    category: 'network_connection',
    description: 'Source TCP/UDP port',
    example: 'SourcePort > 49152',
    logSources: ['windows_sysmon', 'firewall', 'generic'],
    dataType: 'number',
    aliases: ['source_port', 'src_port', 'spt']
  },
  {
    name: 'DestinationPort',
    category: 'network_connection',
    description: 'Destination TCP/UDP port',
    example: 'DestinationPort in [135, 139, 445]',
    logSources: ['windows_sysmon', 'firewall', 'generic'],
    dataType: 'number',
    commonValues: ['80', '443', '445', '135', '139', '3389', '22', '21'],
    aliases: ['destination_port', 'dest_port', 'dst_port', 'dpt']
  },
  {
    name: 'Protocol',
    category: 'network_connection',
    description: 'Network protocol',
    example: 'Protocol = "TCP"',
    logSources: ['windows_sysmon', 'firewall', 'generic'],
    dataType: 'string',
    commonValues: ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS'],
    aliases: ['protocol', 'proto']
  },
  {
    name: 'SourceHostname',
    category: 'network_connection',
    description: 'Source hostname',
    example: 'SourceHostname contains "workstation"',
    logSources: ['windows_sysmon', 'firewall'],
    dataType: 'string',
    aliases: ['source_hostname']
  },
  {
    name: 'DestinationHostname',
    category: 'network_connection',
    description: 'Destination hostname',
    example: 'DestinationHostname = "malicious.com"',
    logSources: ['windows_sysmon', 'firewall', 'dns'],
    dataType: 'string',
    aliases: ['destination_hostname']
  },
  {
    name: 'Initiated',
    category: 'network_connection',
    description: 'Connection initiated (true/false)',
    example: 'Initiated = true',
    logSources: ['windows_sysmon'],
    dataType: 'boolean',
    aliases: ['initiated']
  },

  // ==================== FILE FIELDS ====================
  {
    name: 'TargetFilename',
    category: 'file_event',
    description: 'File path',
    example: 'TargetFilename contains "\\\\Temp\\\\"',
    logSources: ['windows_sysmon', 'linux_auditd'],
    dataType: 'string',
    aliases: ['target_filename', 'file', 'filename', 'filepath', 'file_path', 'fname']
  },
  {
    name: 'CreationUtcTime',
    category: 'file_event',
    description: 'File creation timestamp',
    example: 'CreationUtcTime exists',
    logSources: ['windows_sysmon'],
    dataType: 'timestamp',
    aliases: ['creation_utc_time']
  },

  // ==================== HASH FIELDS ====================
  {
    name: 'Hashes',
    category: 'file_event',
    description: 'File hashes (MD5, SHA1, SHA256)',
    example: 'Hashes contains "MD5=1234567890ABCDEF"',
    logSources: ['windows_sysmon', 'linux_auditd'],
    dataType: 'string',
    aliases: ['hashes', 'hash', 'md5', 'sha1', 'sha256', 'filehash']
  },

  // ==================== SYSTEM FIELDS ====================
  {
    name: 'Computer',
    category: 'system',
    description: 'Computer/hostname',
    example: 'Computer = "WORKSTATION01"',
    logSources: ['windows_sysmon', 'windows_security', 'windows_powershell'],
    dataType: 'string',
    aliases: ['computer', 'hostname', 'host', 'node']
  },
  {
    name: 'EventID',
    category: 'system',
    description: 'Event identifier',
    example: 'EventID = 1',
    logSources: ['windows_sysmon', 'windows_security', 'windows_powershell'],
    dataType: 'number',
    commonValues: ['1', '3', '7', '8', '10', '11', '4624', '4625', '4688'],
    aliases: ['event_id', 'eventid', 'event_type', 'type']
  },
  {
    name: 'EventTime',
    category: 'system',
    description: 'Event timestamp',
    example: 'EventTime exists',
    logSources: ['windows_sysmon', 'windows_security'],
    dataType: 'timestamp',
    aliases: ['event_time', 'eventtime', 'utc_time', 'timestamp']
  },
  {
    name: 'Channel',
    category: 'system',
    description: 'Windows event log channel',
    example: 'Channel = "Microsoft-Windows-Sysmon/Operational"',
    logSources: ['windows_sysmon', 'windows_security', 'windows_powershell'],
    dataType: 'string',
    commonValues: ['Security', 'System', 'Application', 'Microsoft-Windows-Sysmon/Operational'],
    aliases: ['channel']
  },
  {
    name: 'Provider',
    category: 'system',
    description: 'Event log provider',
    example: 'Provider = "Microsoft-Windows-Sysmon"',
    logSources: ['windows_sysmon', 'windows_security'],
    dataType: 'string',
    aliases: ['provider']
  },
  {
    name: 'Level',
    category: 'system',
    description: 'Event severity level',
    example: 'Level = "Error"',
    logSources: ['windows_sysmon', 'windows_security', 'generic'],
    dataType: 'string',
    commonValues: ['Information', 'Warning', 'Error', 'Critical'],
    aliases: ['severity', 'level']
  },

  // ==================== REGISTRY FIELDS ====================
  {
    name: 'TargetObject',
    category: 'registry_event',
    description: 'Registry key path',
    example: 'TargetObject contains "\\\\CurrentVersion\\\\Run"',
    logSources: ['windows_sysmon'],
    dataType: 'string',
    aliases: ['target_object', 'registry_key', 'registry_path']
  },
  {
    name: 'Details',
    category: 'registry_event',
    description: 'Registry value data',
    example: 'Details contains "malicious"',
    logSources: ['windows_sysmon'],
    dataType: 'string',
    aliases: ['details', 'registry_value']
  },
  {
    name: 'EventType',
    category: 'registry_event',
    description: 'Registry operation type',
    example: 'EventType = "SetValue"',
    logSources: ['windows_sysmon'],
    dataType: 'string',
    commonValues: ['SetValue', 'CreateKey', 'DeleteKey', 'DeleteValue'],
    aliases: ['event_type_reg']
  },

  // ==================== DNS FIELDS ====================
  {
    name: 'QueryName',
    category: 'dns_query',
    description: 'DNS query name',
    example: 'QueryName contains "malicious.com"',
    logSources: ['windows_sysmon', 'dns'],
    dataType: 'string',
    aliases: ['query_name', 'query', 'dns_query']
  },
  {
    name: 'QueryType',
    category: 'dns_query',
    description: 'DNS query type',
    example: 'QueryType = "A"',
    logSources: ['dns'],
    dataType: 'string',
    commonValues: ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'PTR'],
    aliases: ['query_type']
  },
  {
    name: 'QueryStatus',
    category: 'dns_query',
    description: 'DNS query status',
    example: 'QueryStatus = 0',
    logSources: ['windows_sysmon', 'dns'],
    dataType: 'number',
    aliases: ['query_status']
  },
  {
    name: 'QueryResults',
    category: 'dns_query',
    description: 'DNS query results',
    example: 'QueryResults contains "192.168.1.1"',
    logSources: ['windows_sysmon', 'dns'],
    dataType: 'string',
    aliases: ['query_results', 'response']
  },

  // ==================== IMAGE/DRIVER LOAD FIELDS ====================
  {
    name: 'ImageLoaded',
    category: 'image_load',
    description: 'Loaded image/DLL path',
    example: 'ImageLoaded contains "\\\\System32\\\\"',
    logSources: ['windows_sysmon'],
    dataType: 'string',
    aliases: ['image_loaded']
  },
  {
    name: 'Signed',
    category: 'image_load',
    description: 'File signature status',
    example: 'Signed = false',
    logSources: ['windows_sysmon'],
    dataType: 'boolean',
    aliases: ['signed']
  },
  {
    name: 'Signature',
    category: 'image_load',
    description: 'File signature',
    example: 'Signature contains "Microsoft"',
    logSources: ['windows_sysmon'],
    dataType: 'string',
    aliases: ['signature']
  },
  {
    name: 'SignatureStatus',
    category: 'image_load',
    description: 'Signature validation status',
    example: 'SignatureStatus = "Valid"',
    logSources: ['windows_sysmon'],
    dataType: 'string',
    commonValues: ['Valid', 'Invalid', 'Unsigned'],
    aliases: ['signature_status']
  },

  // ==================== FILE METADATA FIELDS ====================
  {
    name: 'Company',
    category: 'file_event',
    description: 'File company metadata',
    example: 'Company = "Microsoft Corporation"',
    logSources: ['windows_sysmon'],
    dataType: 'string',
    aliases: ['company']
  },
  {
    name: 'Description',
    category: 'file_event',
    description: 'File description metadata',
    example: 'Description contains "system"',
    logSources: ['windows_sysmon'],
    dataType: 'string',
    aliases: ['description']
  },
  {
    name: 'Product',
    category: 'file_event',
    description: 'File product metadata',
    example: 'Product = "Microsoft Windows"',
    logSources: ['windows_sysmon'],
    dataType: 'string',
    aliases: ['product']
  },
  {
    name: 'FileVersion',
    category: 'file_event',
    description: 'File version',
    example: 'FileVersion exists',
    logSources: ['windows_sysmon'],
    dataType: 'string',
    aliases: ['file_version']
  },
  {
    name: 'OriginalFileName',
    category: 'file_event',
    description: 'Original file name',
    example: 'OriginalFileName = "cmd.exe"',
    logSources: ['windows_sysmon'],
    dataType: 'string',
    aliases: ['original_file_name']
  },

  // ==================== AUTHENTICATION FIELDS ====================
  {
    name: 'LogonType',
    category: 'authentication',
    description: 'Windows logon type',
    example: 'LogonType = 3',
    logSources: ['windows_security'],
    dataType: 'number',
    commonValues: ['2', '3', '4', '5', '7', '8', '9', '10', '11'],
    aliases: ['logon_type']
  },
  {
    name: 'AuthenticationPackageName',
    category: 'authentication',
    description: 'Authentication package used',
    example: 'AuthenticationPackageName = "NTLM"',
    logSources: ['windows_security'],
    dataType: 'string',
    commonValues: ['NTLM', 'Kerberos', 'Negotiate'],
    aliases: ['authentication_package_name']
  },
  {
    name: 'WorkstationName',
    category: 'authentication',
    description: 'Source workstation name',
    example: 'WorkstationName exists',
    logSources: ['windows_security'],
    dataType: 'string',
    aliases: ['workstation_name']
  },
  {
    name: 'IpAddress',
    category: 'authentication',
    description: 'Source IP address for logon',
    example: 'IpAddress = "192.168.1.100"',
    logSources: ['windows_security'],
    dataType: 'string',
    aliases: ['source_network_address', 'ip_address']
  },
  {
    name: 'LogonProcessName',
    category: 'authentication',
    description: 'Logon process name',
    example: 'LogonProcessName exists',
    logSources: ['windows_security'],
    dataType: 'string',
    aliases: ['logon_process_name']
  },

  // ==================== WEB/PROXY FIELDS ====================
  {
    name: 'c-ip',
    category: 'web_proxy',
    description: 'Client IP address',
    example: 'c-ip = "192.168.1.100"',
    logSources: ['web_proxy'],
    dataType: 'string',
    aliases: ['c-ip']
  },
  {
    name: 'cs-username',
    category: 'web_proxy',
    description: 'Client username',
    example: 'cs-username contains "admin"',
    logSources: ['web_proxy'],
    dataType: 'string',
    aliases: ['cs-username']
  },
  {
    name: 'cs-method',
    category: 'web_proxy',
    description: 'HTTP method',
    example: 'cs-method = "POST"',
    logSources: ['web_proxy'],
    dataType: 'string',
    commonValues: ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'],
    aliases: ['cs-method']
  },
  {
    name: 'c-uri',
    category: 'web_proxy',
    description: 'Request URI',
    example: 'c-uri contains "/admin"',
    logSources: ['web_proxy'],
    dataType: 'string',
    aliases: ['cs-uri-stem', 'c-uri']
  },
  {
    name: 'sc-status',
    category: 'web_proxy',
    description: 'HTTP status code',
    example: 'sc-status = 200',
    logSources: ['web_proxy'],
    dataType: 'number',
    commonValues: ['200', '301', '302', '400', '401', '403', '404', '500', '502', '503'],
    aliases: ['sc-status']
  },

  // ==================== POWERSHELL FIELDS ====================
  {
    name: 'ScriptBlockText',
    category: 'powershell',
    description: 'PowerShell script block content',
    example: 'ScriptBlockText contains "Invoke-Expression"',
    logSources: ['windows_powershell'],
    dataType: 'string',
    aliases: ['script_block_text']
  },
  {
    name: 'ScriptBlockId',
    category: 'powershell',
    description: 'PowerShell script block ID',
    example: 'ScriptBlockId exists',
    logSources: ['windows_powershell'],
    dataType: 'string',
    aliases: ['script_block_id']
  },
  {
    name: 'Path',
    category: 'powershell',
    description: 'PowerShell script path',
    example: 'Path contains "\\\\Temp\\\\"',
    logSources: ['windows_powershell'],
    dataType: 'string',
    aliases: ['path']
  },
  {
    name: 'HostApplication',
    category: 'powershell',
    description: 'PowerShell host application',
    example: 'HostApplication contains "powershell.exe"',
    logSources: ['windows_powershell'],
    dataType: 'string',
    aliases: ['host_application']
  },

  // ==================== SERVICE FIELDS ====================
  {
    name: 'ServiceName',
    category: 'service_creation',
    description: 'Windows service name',
    example: 'ServiceName contains "malicious"',
    logSources: ['windows_sysmon', 'windows_security'],
    dataType: 'string',
    aliases: ['service_name']
  },
  {
    name: 'ServiceFileName',
    category: 'service_creation',
    description: 'Service executable path',
    example: 'ServiceFileName contains "\\\\Temp\\\\"',
    logSources: ['windows_sysmon', 'windows_security'],
    dataType: 'string',
    aliases: ['service_file_name']
  },

  // ==================== FIREWALL FIELDS ====================
  {
    name: 'Action',
    category: 'firewall',
    description: 'Firewall action',
    example: 'Action = "Block"',
    logSources: ['firewall'],
    dataType: 'string',
    commonValues: ['Allow', 'Block', 'Drop', 'Deny'],
    aliases: ['action']
  },
  {
    name: 'Direction',
    category: 'firewall',
    description: 'Traffic direction',
    example: 'Direction = "Inbound"',
    logSources: ['firewall'],
    dataType: 'string',
    commonValues: ['Inbound', 'Outbound'],
    aliases: ['direction']
  },
  {
    name: 'Application',
    category: 'firewall',
    description: 'Application path',
    example: 'Application contains "chrome.exe"',
    logSources: ['firewall'],
    dataType: 'string',
    aliases: ['application']
  },
  {
    name: 'RuleName',
    category: 'firewall',
    description: 'Firewall rule name',
    example: 'RuleName exists',
    logSources: ['firewall'],
    dataType: 'string',
    aliases: ['rule_name']
  },

  // ==================== CLOUD AWS FIELDS ====================
  {
    name: 'EventName',
    category: 'cloud_aws',
    description: 'AWS CloudTrail event name',
    example: 'EventName = "ConsoleLogin"',
    logSources: ['aws_cloudtrail'],
    dataType: 'string',
    aliases: ['event_name']
  },
  {
    name: 'EventSource',
    category: 'cloud_aws',
    description: 'AWS service source',
    example: 'EventSource = "iam.amazonaws.com"',
    logSources: ['aws_cloudtrail'],
    dataType: 'string',
    aliases: ['event_source']
  },
  {
    name: 'ErrorCode',
    category: 'cloud_aws',
    description: 'AWS error code',
    example: 'ErrorCode = "AccessDenied"',
    logSources: ['aws_cloudtrail'],
    dataType: 'string',
    aliases: ['error_code']
  },
  {
    name: 'UserAgent',
    category: 'cloud_aws',
    description: 'User agent string',
    example: 'UserAgent contains "aws-cli"',
    logSources: ['aws_cloudtrail', 'azure_activity', 'web_proxy'],
    dataType: 'string',
    aliases: ['aws_user_agent', 'c-useragent']
  },

  // ==================== CATEGORY FIELD ====================
  {
    name: 'Category',
    category: 'system',
    description: 'Auto-detected SIGMA category',
    example: 'Category = "process_creation"',
    logSources: ['windows_sysmon', 'windows_security', 'linux_auditd', 'generic'],
    dataType: 'string',
    commonValues: [
      'process_creation',
      'network_connection',
      'file_event',
      'registry_event',
      'dns_query',
      'authentication',
      'image_load',
      'service_creation',
      'powershell'
    ],
    aliases: ['category']
  }
];

/**
 * Get fields filtered by log source
 */
export function getFieldsForLogSource(logSource: SigmaLogSource): SigmaField[] {
  return SIGMA_FIELDS.filter(field =>
    field.logSources.includes(logSource) || field.logSources.includes('generic')
  );
}

/**
 * Get fields filtered by category
 */
export function getFieldsByCategory(category: SigmaFieldCategory): SigmaField[] {
  return SIGMA_FIELDS.filter(field => field.category === category);
}

/**
 * Get field by name (case-insensitive)
 */
export function getFieldByName(name: string): SigmaField | undefined {
  return SIGMA_FIELDS.find(field =>
    field.name.toLowerCase() === name.toLowerCase() ||
    field.aliases?.some(alias => alias.toLowerCase() === name.toLowerCase())
  );
}

/**
 * Resolve field alias to SIGMA field name
 */
export function resolveFieldAlias(fieldName: string): string {
  const field = getFieldByName(fieldName);
  return field ? field.name : fieldName;
}

/**
 * Get all unique categories
 */
export function getAllCategories(): SigmaFieldCategory[] {
  const categories = new Set(SIGMA_FIELDS.map(f => f.category));
  return Array.from(categories);
}

/**
 * Get category display name
 */
export function getCategoryDisplayName(category: SigmaFieldCategory): string {
  const displayNames: Record<SigmaFieldCategory, string> = {
    process_creation: 'Process Creation',
    network_connection: 'Network Connection',
    file_event: 'File Event',
    registry_event: 'Registry Event',
    dns_query: 'DNS Query',
    authentication: 'Authentication',
    image_load: 'Image/DLL Load',
    service_creation: 'Service Creation',
    powershell: 'PowerShell',
    firewall: 'Firewall',
    web_proxy: 'Web Proxy',
    cloud_aws: 'Cloud - AWS',
    cloud_azure: 'Cloud - Azure',
    cloud_gcp: 'Cloud - GCP',
    system: 'System',
    generic: 'Generic'
  };
  return displayNames[category];
}

/**
 * Get log source display name
 */
export function getLogSourceDisplayName(logSource: SigmaLogSource): string {
  const displayNames: Record<SigmaLogSource, string> = {
    windows_sysmon: 'Windows Sysmon',
    windows_security: 'Windows Security',
    windows_powershell: 'Windows PowerShell',
    linux_auditd: 'Linux Auditd',
    linux_syslog: 'Linux Syslog',
    aws_cloudtrail: 'AWS CloudTrail',
    azure_activity: 'Azure Activity',
    gcp_audit: 'GCP Audit',
    web_proxy: 'Web Proxy',
    firewall: 'Firewall',
    dns: 'DNS',
    generic: 'Generic'
  };
  return displayNames[logSource];
}

/**
 * Get all log sources
 */
export function getAllLogSources(): SigmaLogSource[] {
  return [
    'windows_sysmon',
    'windows_security',
    'windows_powershell',
    'linux_auditd',
    'linux_syslog',
    'aws_cloudtrail',
    'azure_activity',
    'gcp_audit',
    'web_proxy',
    'firewall',
    'dns',
    'generic'
  ];
}

/**
 * Get suggested operators for a field data type
 */
export function getSuggestedOperators(dataType: SigmaFieldDataType): string[] {
  const operatorMap: Record<SigmaFieldDataType, string[]> = {
    string: ['=', '!=', 'contains', 'startswith', 'endswith', 'matches', 'in', 'not in'],
    number: ['=', '!=', '>', '<', '>=', '<=', 'in', 'not in'],
    boolean: ['=', '!='],
    array: ['contains', 'in', 'not in'],
    timestamp: ['=', '!=', '>', '<', '>=', '<=']
  };
  return operatorMap[dataType] || ['=', '!='];
}
