-- -----------------------------------------------------------------------
-- OWASP CRS Plugin
-- Copyright (c) 2024-2025 Core Rule Set project. All rights reserved.
--
-- The OWASP CRS plugins are distributed under
-- Apache Software License (ASL) version 2
-- Please see the enclosed LICENSE file for full details.
-- -----------------------------------------------------------------------

function main()
	pcall(require, "m")
	local ok, DBI = pcall(require, "DBI")
	if not ok then
		m.log(2, "Database Logging Plugin ERROR: DBI library not installed, please install it or disable this plugin.")
		return nil
	end
	local db_type = m.getvar("tx.database-logging-plugin_db_type", "none")
	local db_name = m.getvar("tx.database-logging-plugin_db_name", "none")
	if db_type == "MySQL" or db_type == "PostgreSQL" then
		db_login = m.getvar("tx.database-logging-plugin_db_login", "none")
		db_password = m.getvar("tx.database-logging-plugin_db_password", "none")
		db_host = m.getvar("tx.database-logging-plugin_db_host", "none")
		db_port = m.getvar("tx.database-logging-plugin_db_port", "none")
	elseif db_type == "SQLite3" then
		db_login = nil
		db_password = nil
		db_host = nil
		db_port = nil
	else
		m.log(2, string.format("Database Logging Plugin ERROR: Unknown database type: %s.", db_type))
		return nil
	end
	local webserver_error_log = m.getvars("WEBSERVER_ERROR_LOG", "none")
	local rules_data = {}
	local total_score = 0
	local score_notice = tonumber(m.getvar("tx.notice_anomaly_score", "none"))
	local score_warning = tonumber(m.getvar("tx.warning_anomaly_score", "none"))
	local score_error = tonumber(m.getvar("tx.error_anomaly_score", "none"))
	local score_critical = tonumber(m.getvar("tx.critical_anomaly_score", "none"))
	for k, v in pairs(webserver_error_log) do
		if string.match(v["value"], "ModSecurity") and string.match(v["value"], "PCRE limits exceeded") == nil then
			r = {}
			r["id"] = string.match(v["value"], ' %[id "(%d+)"%] ')
			if r["id"] ~= "980130" and r["id"] ~= "949110" then
				r["message"] = string.match(v["value"], ' %[msg "(.-)"%] ')
				r["data"] = string.match(v["value"], ' %[data "(.-)"%] ')
				r["severity"] = string.match(v["value"], ' %[severity "(.-)"%] ')
				if r["severity"] == "NOTICE" then
					total_score = total_score + score_notice
				elseif r["severity"] == "WARNING" then
					total_score = total_score + score_warning
				elseif r["severity"] == "ERROR" then
					total_score = total_score + score_error
				elseif r["severity"] == "CRITICAL" then
					total_score = total_score + score_critical
				end
				r["variable"] = string.match(v["value"], 'Pattern match ".-" at (.-)%. ')
				if r["variable"] == nil then
					r["variable"] = string.match(v["value"], "Matched Data: .- found within (.-): ")
					if r["variable"] == nil then
						r["variable"] = string.match(v["value"], 'String match within ".-" at (.-)%. ')
						if r["variable"] == nil then
							r["variable"] = string.match(v["value"], 'String match ".-" at (.-)%. ')
							if r["variable"] == nil then
								r["variable"] = string.match(v["value"], 'Matched phrase ".-" at (.+)%. %[file')
								if r["variable"] == nil then
									r["variable"] = string.match(v["value"], 'Match of ".-" against "(.-)" required%. ')
									if r["variable"] == nil then
										r["variable"] = string.match(v["value"], "Found %d+ byte%(s%) in (.-) outside range:")
										if r["variable"] == nil then
											r["variable"] = string.match(v["value"], "Operator EQ matched %d+ at (.-)%. ")
											if r["variable"] == nil then
												r["variable"] = string.match(v["value"], "Invalid URL Encoding: Non%-hexadecimal digits used at (.-)%. ")
												if r["variable"] == nil then
													r["variable"] = string.match(v["value"], "Not enough characters at the end of input at (.-)%. ")
													if r["variable"] == nil then
														m.log(2, string.format("Database Logging Plugin WARNING: Unknown variable: %s", v["value"]))
													end
												end
											end
										end
									end
								end
							end
						end
					end
				end
				table.insert(rules_data, r)
			end
		end
	end
	-- No rules were triggered, nothing to log.
	if next(rules_data) == nil then
		return nil
	end
	local ok, dbd, error = pcall(DBI.Connect, db_type, db_name, db_login, db_password, db_host, db_port)
	if not ok then
		m.log(2, string.format("Database Logging Plugin ERROR: Error connecting to database: %s.", dbd))
		return nil
	end
	if not dbd then
		m.log(2, string.format("Database Logging Plugin ERROR: Error connecting to database: %s.", error))
		return nil
	end
	local server_name = m.getvar("SERVER_NAME", "none")
	local remote_addr = m.getvar("REMOTE_ADDR", "none")
	local unique_id = m.getvar("UNIQUE_ID", "none")
	local response_status = m.getvar("RESPONSE_STATUS", "none")
	if db_type == "MySQL" then
		insert_main = dbd:prepare("INSERT INTO `modsecurity_requests` SET timestamp=NOW(), score=?, server_name=?, remote_addr=?, unique_id=?, response_status=?")
		insert_rule = dbd:prepare("INSERT INTO `modsecurity_requests_rules` SET id_request=?, rule_id=?, variable=?, message=?, data=?, severity=?")
	elseif db_type == "SQLite3" then
		insert_main = dbd:prepare("INSERT INTO `modsecurity_requests` VALUES (NULL, datetime('now'), ?, ?, ?, ?, ?)")
		insert_rule = dbd:prepare("INSERT INTO `modsecurity_requests_rules` VALUES (NULL, ?, ?, ?, ?, ?, ?)")
	end
	if not insert_main then
		m.log(2, "Database Logging Plugin ERROR: Cannot insert into modsecurity_requests table.")
		return nil
	end
	if not insert_rule then
		m.log(2, "Database Logging Plugin ERROR: Cannot insert into modsecurity_requests_rules table.")
		return nil
	end
	insert_main:execute(total_score, server_name, remote_addr, unique_id, response_status)
	local request_db_id = dbd:last_id()
	for k, value in pairs(rules_data) do
		insert_rule:execute(request_db_id, value["id"], value["variable"], value["message"], value["data"], value["severity"])
	end
	dbd:commit()
	dbd:close()
	return nil
end
