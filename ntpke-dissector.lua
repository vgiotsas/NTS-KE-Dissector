-- Vasileios Giotsas
-- Lua Wireshark dissector for the NTS-KE protocol
-- https://tools.ietf.org/html/draft-ietf-ntp-using-nts-for-ntp-28#section-4

local default_settings =
{
    enabled      = true,        -- whether this dissector is enabled or not
    ports         = {[123]=true, [4430]=true} -- TCP port numbers for NTS-KE
}

ntske_protocol = Proto("NTS-KE",  "NTS Key Establishment")

-- Record type 0: End of message
-- Record type 1: Next protocol protocol negotiation
-- Record type 2: Error
-- Record type 3: Warning
-- Record type 4: AEAD Algorithm Negotiation
-- Record type 5: New Cookie for NTPv4
-- Record type 6: NTPv4 Server Negotiation
-- Record type 7: NTPv4 Port Negotiation
local record_values = {
                [0] = "End of message",
                [1] = "Next protocol negotiation",
                [2] = "Error",
                [3] = "Warning",
                [4] = "AEAD Algorithm Negotiation",
                [5] = "New Cookie for NTPv4",
                [6] = "NTPv4 Server Negotiation",
                [7] = "NTPv4 Port Negotiation"
        }


-- This nested table holds the IANA identifiers for NTS protocols and AEAD algorithms
-- https://www.iana.org/assignments/nts/nts.xhtml#nts-next-protocols
-- https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml
--
-- It's a nested table, with the key of the outer table representing the record type
-- and the key of the inner table reprenting the IANA Identifier and value
local iana_identifiers = {
				[1] = {
					[0] = "Network Time Protocol version 4 (NTPv4)"
				},
				[4] = {
					[1] = "AEAD_AES_128_GCM",
					[2] = "AEAD_AES_256_GCM",
					[3] = "AEAD_AES_128_CCM",
					[4] = "AEAD_AES_256_CCM",
					[5] = "AEAD_AES_128_GCM_8",
					[6] = "AEAD_AES_256_GCM_8",
					[7] = "AEAD_AES_128_GCM_12",
					[8] = "AEAD_AES_256_GCM_12",
					[9] = "AEAD_AES_128_CCM_SHORT",
					[10] = "AEAD_AES_256_CCM_SHORT",
					[11] = "AEAD_AES_128_CCM_SHORT_8",
					[12] = "AEAD_AES_256_CCM_SHORT_8",
					[13] = "AEAD_AES_128_CCM_SHORT_12",
					[14] = "AEAD_AES_256_CCM_SHORT_12",
					[15] = "AEAD_AES_SIV_CMAC_256",
					[16] = "AEAD_AES_SIV_CMAC_384",
					[17] = "AEAD_AES_SIV_CMAC_512",
					[18] = "AEAD_AES_128_CCM_8",
					[19] = "AEAD_AES_256_CCM_8",
					[20] = "AEAD_AES_128_OCB_TAGLEN128",
					[21] = "AEAD_AES_128_OCB_TAGLEN96",
					[22] = "AEAD_AES_128_OCB_TAGLEN64",
					[23] = "AEAD_AES_192_OCB_TAGLEN128",
					[24] = "AEAD_AES_192_OCB_TAGLEN96",
					[25] = "AEAD_AES_192_OCB_TAGLEN64",
					[26] = "AEAD_AES_256_OCB_TAGLEN128",
					[27] = "AEAD_AES_256_OCB_TAGLEN96",
					[28] = "AEAD_AES_256_OCB_TAGLEN64",
					[29] = "AEAD_CHACHA20_POLY1305",
					[30] = "AEAD_AES_128_GCM_SIV",
					[31] = "AEAD_AES_256_GCM_SIV"
				}
}

-- this table holds the text that should go next to the record body field depending on the record type
local record_body_text = {
	[1] = "Requested NTSK protocols",
	[4] = "Requested AEAD algorithms"
}

record_type = ProtoField.uint16("ntske.record_type", "Record Type", base.HEX)
critical_bit = ProtoField.bool("ntske.critical_bit", "Critical Bit", 16, nil, 0x8000)
record_type_value = ProtoField.uint16("ntske.record_type_value", "Record type value", base.DEC, record_values, 0x7FFF)
message_length = ProtoField.uint16("ntske.message_length", "Message Length", base.DEC)
record_body = ProtoField.new("Record Body", "ntske.body", ftypes.STRING)
local tls_len = Field.new('tls.record.length')

ntske_protocol.fields = {
	record_type,
	critical_bit,
	record_type_value,
	message_length,
	record_body
}

local ntske_len = Field.new('ntske.message_length')

-- Some error expert infos
local error_len_wrong = ProtoExpert.new("ntske.wrong_error_len", "NTS-KE Error message is not 2 octets long",
                                     expert.group.MALFORMED, expert.severity.ERROR)
local error_wrong_cb = ProtoExpert.new("ntske.wrong_cb", "NTS-KE Record has invalid critical bit",
                                     expert.group.MALFORMED, expert.severity.ERROR)
ntske_protocol.experts = {error_len_wrong, error_wrong_cb}


-- Dissects either a Next Protocol Negotiation or an AED Algorithm Negotiation request
dissectProtoRequest = function (buffer, pktinfo, subtree, rtv, current_pointer)
	local msg_len = buffer:range(current_pointer,2):uint()
	current_pointer = current_pointer + 2
	local body_subtree = subtree:add(record_body, buffer(current_pointer, msg_len), record_body_text[rtv])

	-- Each protocol ID is a 16-bit integer
	-- https://www.iana.org/assignments/nts/nts.xhtml#nts-next-protocols
	-- So the message body should be incremented every 2 bytes
	local requested_protocols = {}
	for i = 0, msg_len-1, 2 do
		local proto_id = buffer(current_pointer + i, 2):uint()
		if iana_identifiers[rtv][proto_id] ~= nil then
			requested_protocols[proto_id] = iana_identifiers[rtv][proto_id]
		elseif proto_id <= 32767 then
			requested_protocols[proto_id]  = "Unassigned ID"
		elseif proto_id > 32767 and proto_id < 65535 then
			requested_protocols[proto_id] = "Reserved for Private or Experimental Use"
		end
		body_subtree:add(buffer(current_pointer + i, 2), proto_id ..":", requested_protocols[proto_id] )
	end
	
	return msg_len + current_pointer
end

-- Dissects and error NTS-KE record type
dissectError = function(buffer, pktinfo, tree, subtree, current_pointer)
	error_codes = {
		[0] = "Unrecognized Critical Record",
		[1] = "Bad Request",
		[2] = "Internal Server Error"
	}
	local error_msg = ""
	local msg_len = buffer:range(current_pointer,2):uint()
	current_pointer = current_pointer + 2
	if msg_len ~= 2 then
		tree:add_proto_expert_info(error_len_wrong)
	else
		local error_code = buffer(current_pointer, 2):uint()
		if error_codes[error_code] == nil then
			local body_subtree = subtree:add(record_body, buffer(4, msg_len), "Unknown error code ("..error_code..")")
		else
			local body_subtree = subtree:add(record_body, buffer(4, msg_len), error_codes[error_code] .."("..error_code..")")
		end
	end
	return msg_len + 4
end

-- Checks the validity of the critical bit depending on the record type
checkCriticalBit = function(buffer, pinfo, tree, current_pointer)
	-- get the value of the critical bit
	local critical_bit_value = buffer:range(current_pointer,1):bitfield(0,1)
	-- get the value of the record type
	local rtv = buffer:range(current_pointer,2):bitfield(1,15)
	-- a value of -1 means that the critical bit may or may not be set
	expected_cb = -1
	if record_values[rtv] ~= nil then
		-- the following record types MUST have the critical bit set
		if rtv >= 0 and rtv < 4 then
			expected_cb = 1 
		-- the following record types SHOULD NOT have the critical bit set
		-- for record types 6 and 7 only clients should not set the critical bit
		elseif rtv == 5 or (default_settings.ports[tostring(pinfo.src_port)] == nil and (rtv == 6 or rtv == 7)) then
			expected_cb = 0
		end
	elseif critical_bit_value == 1 then
		pinfo.cols.info = 'Error: Unknown record type with critical bit set'
	end
	
	-- If the critical bit is wrong set the expert info error
	if critical_bit_value ~= expected_cb and expected_cb ~= -1 then
		print(critical_bit_value .." "..rtv.." "..expected_cb.." "..current_pointer)
		tree:add_proto_expert_info(error_wrong_cb)
	end
	
end

-- Sets the text of the Wireshark Info column
setPacketInfo = function(pinfo)
	if default_settings.ports[pinfo.src_port] == nil then
		pinfo.cols.info = "Client Request"
	else
		pinfo.cols.info = "Server Response"
	end
end

function ntske_protocol.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end

	pinfo.cols.protocol = ntske_protocol.name
	local total_len = tls_len()()
	
	local current_pointer = 0
	
	-- A single TCP packet may contain multiple NTS-KE records
	-- so we need to parse them iteratively
	while current_pointer < length do
		-- Add the NTSK-KE message in the protocol tree
		local subtree = tree:add(ntske_protocol, buffer(current_pointer, length-current_pointer))
		-- Get the value of the record type
		local rtv = buffer:range(current_pointer,2):bitfield(1,15)
		local record_type_tree = subtree:add(record_type, buffer(current_pointer,2))
		-- Add the header fields
		record_type_tree:add(critical_bit, buffer(current_pointer,2))
		record_type_tree:add(record_type_value, buffer(current_pointer,2))
		checkCriticalBit(buffer, pinfo, subtree, current_pointer)
		setPacketInfo(pinfo)
		current_pointer = current_pointer + 2
		subtree:add(message_length, buffer(current_pointer,2))
		-- Get the value of the Message Length field
		local msg_len = buffer:range(current_pointer,2):uint()
		print("Check critical bit for rtv: "..rtv .. " and pointer: "..current_pointer)
		-- Parse the Body of the NTS-KE message depending on the Record Type value (rtv)
		-- For protocol or algorithm negotiation
		if rtv == 1 or rtv == 4 then
			current_pointer = dissectProtoRequest(buffer, pinfo, subtree, rtv, current_pointer)
		-- For error messages 
		elseif rtv == 2 then
			current_pointer = dissectError(buffer, pinfo, subtree, current_pointer)
			break
		-- For new cookie or server negotiation 
		elseif rtv == 5 or rtv == 6 then
			s = buffer:range(current_pointer + 2, msg_len):string()
			subtree:add(record_body, buffer(current_pointer+2, msg_len), s)
			current_pointer = current_pointer + 2 + msg_len
		-- For port negotiation
		elseif rtv == 7 then
			port_number = buffer:range(current_pointer + 2, msg_len):uint()
			subtree:add(record_body, buffer(current_pointer+2, msg_len), port_number)
			current_pointer = current_pointer + 2 + msg_len
		-- For end of message
		elseif rtv == 0 then
			break
		-- For anything else
		else
			if msg_len > 0 then
				subtree:add(record_body, buffer(current_pointer+2, ntske_len()()))
			end
			current_pointer = current_pointer + ntske_len()() + 2
		end
	end
end

local tls_port = DissectorTable.get("tls.port")
for k, v in pairs(default_settings.ports) do
  tls_port:add(k, ntske_protocol)
end

