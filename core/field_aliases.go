package core

import (
	"strings"
)

// FieldAliases maps legacy/common field names to SIGMA standard field names
var FieldAliases = map[string]string{
	// Process fields
	"image":               "Image",
	"process_name":        "Image",
	"process":             "Image",
	"command_line":        "CommandLine",
	"commandline":         "CommandLine",
	"command":             "CommandLine",
	"cmd":                 "CommandLine",
	"parent_image":        "ParentImage",
	"parent_process_name": "ParentImage",
	"parent_process":      "ParentImage",
	"parent_command_line": "ParentCommandLine",
	"parent_commandline":  "ParentCommandLine",
	"process_id":          "ProcessId",
	"pid":                 "ProcessId",
	"parent_process_id":   "ParentProcessId",
	"ppid":                "ParentProcessId",
	"current_directory":   "CurrentDirectory",
	"cwd":                 "CurrentDirectory",
	"process_guid":        "ProcessGuid",
	"parent_process_guid": "ParentProcessGuid",
	"integrity_level":     "IntegrityLevel",
	"terminal_session_id": "TerminalSessionId",

	// User fields
	"user":                "User",
	"username":            "User",
	"user_name":           "User",
	"target_user_name":    "TargetUserName",
	"target_user":         "TargetUserName",
	"subject_user_name":   "User",
	"subject_domain_name": "SubjectDomainName",
	"target_domain_name":  "TargetDomainName",
	"logon_id":            "LogonId",
	"user_id":             "User",
	"uid":                 "User",
	"euid":                "User",
	"auid":                "User",

	// Network fields
	"source_ip":            "SourceIp",
	"src_ip":               "SourceIp",
	"src":                  "SourceIp",
	"source_address":       "SourceIp",
	"destination_ip":       "DestinationIp",
	"dest_ip":              "DestinationIp",
	"dst_ip":               "DestinationIp",
	"dst":                  "DestinationIp",
	"destination_address":  "DestinationIp",
	"source_port":          "SourcePort",
	"src_port":             "SourcePort",
	"spt":                  "SourcePort",
	"destination_port":     "DestinationPort",
	"dest_port":            "DestinationPort",
	"dst_port":             "DestinationPort",
	"dpt":                  "DestinationPort",
	"protocol":             "Protocol",
	"proto":                "Protocol",
	"source_hostname":      "SourceHostname",
	"destination_hostname": "DestinationHostname",
	"source_is_ipv6":       "SourceIsIpv6",
	"destination_is_ipv6":  "DestinationIsIpv6",
	"initiated":            "Initiated",

	// File fields
	"target_filename":            "TargetFilename",
	"file":                       "TargetFilename",
	"filename":                   "TargetFilename",
	"filepath":                   "TargetFilename",
	"file_path":                  "TargetFilename",
	"fname":                      "TargetFilename",
	"creation_utc_time":          "CreationUtcTime",
	"previous_creation_utc_time": "PreviousCreationUtcTime",

	// Hash fields
	"hashes":   "Hashes",
	"hash":     "Hashes",
	"md5":      "Hashes",
	"sha1":     "Hashes",
	"sha256":   "Hashes",
	"filehash": "Hashes",

	// System fields
	"computer":   "Computer",
	"hostname":   "Computer",
	"host":       "Computer",
	"node":       "Computer",
	"event_id":   "EventID",
	"eventid":    "EventID",
	"event_type": "EventID",
	"type":       "EventID",
	"event_time": "EventTime",
	"eventtime":  "EventTime",
	"utc_time":   "EventTime",
	"timestamp":  "EventTime",
	"channel":    "Channel",
	"provider":   "Provider",

	// Registry fields
	"target_object":  "TargetObject",
	"registry_key":   "TargetObject",
	"registry_path":  "TargetObject",
	"details":        "Details",
	"registry_value": "Details",
	"event_type_reg": "EventType",

	// DNS fields
	"query_name":    "QueryName",
	"query":         "QueryName",
	"dns_query":     "QueryName",
	"query_type":    "QueryType",
	"query_class":   "QueryClass",
	"query_status":  "QueryStatus",
	"query_results": "QueryResults",
	"response":      "QueryResults",
	"response_code": "ResponseCode",

	// Image/Driver load fields
	"image_loaded":     "ImageLoaded",
	"signed":           "Signed",
	"signature":        "Signature",
	"signature_status": "SignatureStatus",

	// File metadata
	"company":            "Company",
	"description":        "Description",
	"product":            "Product",
	"file_version":       "FileVersion",
	"original_file_name": "OriginalFileName",

	// Authentication fields
	"logon_type":                  "LogonType",
	"authentication_package_name": "AuthenticationPackageName",
	"workstation_name":            "WorkstationName",
	"source_network_address":      "IpAddress",
	"ip_address":                  "IpAddress",
	"logon_process_name":          "LogonProcessName",

	// Web/Proxy fields
	"c-ip":         "c-ip",
	"cs-username":  "cs-username",
	"cs-method":    "cs-method",
	"cs-uri-stem":  "c-uri",
	"c-uri":        "c-uri",
	"cs-uri-query": "c-uri-query",
	"cs-host":      "cs-host",
	"sc-status":    "sc-status",
	"sc-bytes":     "sc-bytes",
	"cs-bytes":     "cs-bytes",
	"time-taken":   "time-taken",
	"cs-version":   "cs-version",
	"c-useragent":  "c-useragent",
	"cs-referrer":  "cs-referrer",
	"referer":      "cs-referrer",

	// PowerShell fields
	"script_block_text": "ScriptBlockText",
	"script_block_id":   "ScriptBlockId",
	"path":              "Path",
	"host_application":  "HostApplication",
	"host_name":         "HostName",
	"host_version":      "HostVersion",
	"context_info":      "ContextInfo",

	// Service fields
	"service_name":      "ServiceName",
	"service_file_name": "ServiceFileName",

	// Firewall fields
	"action":      "Action",
	"direction":   "Direction",
	"application": "Application",
	"rule_name":   "RuleName",

	// Cloud fields (AWS)
	"user_identity.user_name":    "User",
	"user_identity.principal_id": "UserId",
	"source_ip_address":          "SourceIp",
	"event_name":                 "EventName",
	"event_source":               "EventSource",
	"aws_region":                 "Region",
	"aws_user_agent":             "UserAgent",
	"error_code":                 "ErrorCode",
	"error_message":              "ErrorMessage",
	"request_parameters":         "RequestParameters",
	"response_elements":          "ResponseElements",

	// Cloud fields (Azure)
	"identity":              "User",
	"user_principal_name":   "User",
	"location":              "Location",
	"status":                "Status",
	"result_type":           "ResultType",
	"result_description":    "ResultDescription",
	"app_display_name":      "Application",
	"resource_display_name": "Resource",

	// Cloud fields (GCP)
	"principal_email":  "User",
	"caller_ip":        "SourceIp",
	"gcp_service_name": "ServiceName",
	"method_name":      "MethodName",
	"resource_name":    "ResourceName",
	"request":          "RequestParameters",
	"status.code":      "StatusCode",
	"status.message":   "StatusMessage",

	// Category (auto-detected field)
	"category": "Category",

	// Special fields
	"severity": "Level",
	"level":    "Level",
	"message":  "Message",
	"msg":      "Message",
}

// ResolveFieldName resolves a field name using aliases
// Returns the SIGMA standard field name if an alias exists, otherwise returns the original field name
func ResolveFieldName(fieldName string) string {
	// Check if it's an alias
	if sigmaField, exists := FieldAliases[strings.ToLower(fieldName)]; exists {
		return sigmaField
	}

	// Check if it's already a SIGMA field (case-sensitive exact match)
	// This allows direct use of SIGMA fields like "CommandLine", "Image", etc.
	return fieldName
}

// IsTopLevelField checks if a field should be queried at the top level (not in fields subdocument)
func IsTopLevelField(fieldName string) bool {
	topLevelFields := map[string]bool{
		"event_id":      true,
		"timestamp":     true,
		"@timestamp":    true,
		"source_format": true,
		"source_ip":     true,
		"event_type":    true,
		"severity":      true,
	}

	return topLevelFields[strings.ToLower(fieldName)]
}

// GetQueryFieldName returns the full field path for querying
// - Top-level fields are returned as-is
// - SIGMA/custom fields are prefixed with "fields."
func GetQueryFieldName(fieldName string) string {
	// Resolve alias first
	resolved := ResolveFieldName(fieldName)

	// Special handling for @timestamp
	if resolved == "@timestamp" || fieldName == "@timestamp" {
		return "timestamp"
	}

	// Check if it's a top-level field
	if IsTopLevelField(resolved) {
		return resolved
	}

	// For all other fields, they're stored in the fields subdocument
	// Check if it already has the "fields." prefix
	if strings.HasPrefix(resolved, "fields.") {
		return resolved
	}

	return "fields." + resolved
}
