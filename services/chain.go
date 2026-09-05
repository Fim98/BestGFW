package services

import (
	"encoding/json"
	"freegfw/database"
	"freegfw/models"
)

// 链式出站：把某个通过「链接」功能连接的远端节点绑定为默认出站，
// 入站流量在本站终结协议后，由核心经该节点转发出去（本站 → 远端）。

// GetChainLink 返回被绑定为链式出站的节点。
// 未绑定、同步未成功或没有服务器配置时返回 nil（回落为直连/WARP）。
func GetChainLink() *models.Link {
	var s models.Setting
	database.DB.Where("key = ?", "chain_link_id").Limit(1).Find(&s)
	if len(s.Value) == 0 {
		return nil
	}
	var id uint
	if err := json.Unmarshal(s.Value, &id); err != nil || id == 0 {
		return nil
	}
	var link models.Link
	if err := database.DB.First(&link, id).Error; err != nil {
		return nil
	}
	if link.LastSyncStatus != "success" || len(link.Server) == 0 {
		return nil
	}
	return &link
}

// GetChainUUID 返回用于链式出站的本机用户凭证。
// 远端节点通过 Link 同步已信任本机用户，因此任一本机用户的 UUID 在远端均有效。
func GetChainUUID() string {
	var u models.User
	if err := database.DB.First(&u).Error; err != nil {
		return ""
	}
	return u.UUID
}

// ChainRemoteName 返回链式节点的显示名（用于订阅节点命名）。
func ChainRemoteName(link *models.Link) string {
	var server map[string]interface{}
	json.Unmarshal(link.Server, &server)
	if server != nil {
		if t, ok := server["title"].(string); ok && t != "" {
			return t
		}
	}
	if link.Name != nil && *link.Name != "" {
		return *link.Name
	}
	if link.IP != nil && *link.IP != "" {
		return *link.IP
	}
	return "outbound"
}

// ChainOutbound 构建当前引擎可用的链式出站配置。
// 返回 nil 表示链式出站不生效（未绑定/协议不支持/缺少凭证）。
func ChainOutbound() map[string]interface{} {
	link := GetChainLink()
	if link == nil {
		return nil
	}
	var server map[string]interface{}
	if err := json.Unmarshal(link.Server, &server); err != nil || server == nil {
		return nil
	}
	uuid := GetChainUUID()
	if uuid == "" {
		return nil
	}
	host := ""
	if link.IP != nil {
		host = *link.IP
	}
	if host == "" {
		return nil
	}

	engine := "singbox"
	if coreInstance != nil {
		engine = coreInstance.CurrentEngine
	}

	if engine == "xray" {
		return BuildXrayChainOutbound(server, host, uuid)
	}
	return BuildSingboxChainOutbound(server, host, uuid)
}

// GetChainPort 返回链式入站端口（默认 8443），0 表示配置非法。
func GetChainPort() int {
	var s models.Setting
	database.DB.Where("key = ?", "chain_port").Limit(1).Find(&s)
	if len(s.Value) == 0 {
		return 8443
	}
	var port int
	if err := json.Unmarshal(s.Value, &port); err != nil || port <= 0 || port > 65535 {
		return 8443
	}
	return port
}

// ServerPort 从 server 配置中解析监听端口。
func ServerPort(server map[string]interface{}) int {
	switch v := server["listen_port"].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}

// cloneMap 深拷贝配置 map，避免链式入站与主入站相互影响。
func cloneMap(m map[string]interface{}) map[string]interface{} {
	b, _ := json.Marshal(m)
	var out map[string]interface{}
	json.Unmarshal(b, &out)
	return out
}

func chainPort(server map[string]interface{}) int {
	switch v := server["listen_port"].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}

func chainHostHeader(tr map[string]interface{}) string {
	if tr == nil {
		return ""
	}
	if h, ok := tr["host"].(string); ok && h != "" {
		return h
	}
	if arr, ok := tr["host"].([]interface{}); ok && len(arr) > 0 {
		if s, ok := arr[0].(string); ok {
			return s
		}
	}
	return ""
}

// BuildSingboxChainOutbound 根据远端节点 server 配置构建 sing-box 客户端出站。
func BuildSingboxChainOutbound(server map[string]interface{}, host, uuid string) map[string]interface{} {
	if server == nil || host == "" || uuid == "" {
		return nil
	}
	serverType, _ := server["type"].(string)
	port := chainPort(server)
	if port <= 0 {
		return nil
	}

	ob := map[string]interface{}{
		"tag":         "chain",
		"server":      host,
		"server_port": port,
	}

	switch serverType {
	case "vmess":
		ob["type"] = "vmess"
		ob["uuid"] = uuid
		ob["security"] = "auto"
		ob["alter_id"] = 0
	case "vless":
		ob["type"] = "vless"
		ob["uuid"] = uuid
		if flow, ok := server["flow"].(string); ok && flow != "" {
			ob["flow"] = flow
		}
	case "trojan":
		ob["type"] = "trojan"
		ob["password"] = uuid
	case "shadowsocks":
		method, _ := server["method"].(string)
		if method == "" {
			return nil
		}
		ob["type"] = "shadowsocks"
		ob["method"] = method
		ob["password"] = uuid
	case "anytls":
		ob["type"] = "anytls"
		ob["password"] = uuid
	case "hysteria2":
		ob["type"] = "hysteria2"
		ob["password"] = uuid
	default:
		// sing-box 出站不支持该协议（如 naive）
		return nil
	}

	if tlsOut := buildSingboxChainTLS(server, host); tlsOut != nil {
		ob["tls"] = tlsOut
	}
	if tr := buildSingboxChainTransport(server); tr != nil {
		ob["transport"] = tr
	}
	return ob
}

func buildSingboxChainTLS(server map[string]interface{}, host string) map[string]interface{} {
	tlsCfg, _ := server["tls"].(map[string]interface{})
	if tlsCfg == nil || tlsCfg["enabled"] != true {
		return nil
	}
	out := map[string]interface{}{"enabled": true}
	sn, _ := tlsCfg["server_name"].(string)
	if sn == "" {
		sn = host
	}
	out["server_name"] = sn

	if reality, ok := tlsCfg["reality"].(map[string]interface{}); ok && reality["enabled"] == true {
		rOut := map[string]interface{}{"enabled": true}
		if pk, ok := reality["public_key"].(string); ok && pk != "" {
			rOut["public_key"] = pk
		}
		if sids, ok := reality["short_id"].([]interface{}); ok && len(sids) > 0 {
			if sid, ok := sids[0].(string); ok {
				rOut["short_id"] = sid
			}
		}
		out["reality"] = rOut
		// Reality 客户端必须带 uTLS 指纹
		out["utls"] = map[string]interface{}{"enabled": true, "fingerprint": "chrome"}
	}
	return out
}

func buildSingboxChainTransport(server map[string]interface{}) map[string]interface{} {
	tr, _ := server["transport"].(map[string]interface{})
	if tr == nil {
		return nil
	}
	t, _ := tr["type"].(string)
	out := map[string]interface{}{}
	switch t {
	case "ws":
		out["type"] = "ws"
		if p, ok := tr["path"].(string); ok && p != "" {
			out["path"] = p
		}
		if h := chainHostHeader(tr); h != "" {
			out["headers"] = map[string]interface{}{"Host": h}
		}
		return out
	case "http", "h2":
		out["type"] = "http"
		if p, ok := tr["path"].(string); ok && p != "" {
			out["path"] = p
		}
		if h := chainHostHeader(tr); h != "" {
			out["host"] = []string{h}
		}
		return out
	case "grpc":
		out["type"] = "grpc"
		if p, ok := tr["path"].(string); ok && p != "" {
			out["service_name"] = p
		}
		return out
	case "httpupgrade":
		out["type"] = "httpupgrade"
		if p, ok := tr["path"].(string); ok && p != "" {
			out["path"] = p
		}
		if h := chainHostHeader(tr); h != "" {
			out["host"] = h
		}
		return out
	}
	return nil
}

// BuildXrayChainOutbound 根据远端节点 server 配置构建 Xray 客户端出站。
func BuildXrayChainOutbound(server map[string]interface{}, host, uuid string) map[string]interface{} {
	if server == nil || host == "" || uuid == "" {
		return nil
	}
	serverType, _ := server["type"].(string)
	port := chainPort(server)
	if port <= 0 {
		return nil
	}

	stream := map[string]interface{}{"network": "tcp"}
	tlsCfg, _ := server["tls"].(map[string]interface{})
	if tlsCfg != nil && tlsCfg["enabled"] == true {
		sn, _ := tlsCfg["server_name"].(string)
		if sn == "" {
			sn = host
		}
		reality, _ := tlsCfg["reality"].(map[string]interface{})
		if reality != nil && reality["enabled"] == true {
			rSettings := map[string]interface{}{"serverName": sn, "fingerprint": "chrome"}
			if pk, ok := reality["public_key"].(string); ok && pk != "" {
				rSettings["publicKey"] = pk
			}
			if sids, ok := reality["short_id"].([]interface{}); ok && len(sids) > 0 {
				if sid, ok := sids[0].(string); ok && sid != "" {
					rSettings["shortId"] = sid
				}
			}
			stream["security"] = "reality"
			stream["realitySettings"] = rSettings
		} else {
			stream["security"] = "tls"
			stream["tlsSettings"] = map[string]interface{}{
				"serverName":    sn,
				"allowInsecure": false,
				"fingerprint":   "chrome",
			}
		}
	}

	transport, _ := server["transport"].(map[string]interface{})
	if transport != nil {
		if t, ok := transport["type"].(string); ok && t != "" {
			if t == "splithttp" {
				t = "xhttp"
			}
			stream["network"] = t
		}
		switch stream["network"] {
		case "ws":
			ws := map[string]interface{}{}
			if p, ok := transport["path"].(string); ok && p != "" {
				ws["path"] = p
			}
			if h := chainHostHeader(transport); h != "" {
				ws["headers"] = map[string]interface{}{"Host": h}
			}
			stream["wsSettings"] = ws
		case "xhttp":
			xh := map[string]interface{}{}
			if p, ok := transport["path"].(string); ok && p != "" {
				xh["path"] = p
			}
			if h := chainHostHeader(transport); h != "" {
				xh["host"] = h
			}
			stream["xhttpSettings"] = xh
		case "grpc":
			g := map[string]interface{}{}
			if p, ok := transport["path"].(string); ok && p != "" {
				g["serviceName"] = p
			}
			stream["grpcSettings"] = g
		case "http":
			h2 := map[string]interface{}{}
			if p, ok := transport["path"].(string); ok && p != "" {
				h2["path"] = p
			}
			if h := chainHostHeader(transport); h != "" {
				h2["host"] = []string{h}
			}
			stream["httpSettings"] = h2
		}
	}

	outbound := map[string]interface{}{"tag": "chain", "streamSettings": stream}
	switch serverType {
	case "vmess":
		outbound["protocol"] = "vmess"
		outbound["settings"] = map[string]interface{}{
			"vnext": []interface{}{map[string]interface{}{
				"address": host,
				"port":    port,
				"users": []interface{}{map[string]interface{}{
					"id": uuid, "security": "auto", "alterId": 0,
				}},
			}},
		}
	case "vless":
		user := map[string]interface{}{"id": uuid, "encryption": "none"}
		if flow, ok := server["flow"].(string); ok && flow != "" {
			user["flow"] = flow
		}
		outbound["protocol"] = "vless"
		outbound["settings"] = map[string]interface{}{
			"vnext": []interface{}{map[string]interface{}{
				"address": host, "port": port, "users": []interface{}{user},
			}},
		}
	case "trojan":
		outbound["protocol"] = "trojan"
		outbound["settings"] = map[string]interface{}{
			"servers": []interface{}{map[string]interface{}{
				"address": host, "port": port, "password": uuid,
			}},
		}
	case "shadowsocks":
		method, _ := server["method"].(string)
		if method == "" {
			return nil
		}
		outbound["protocol"] = "shadowsocks"
		outbound["settings"] = map[string]interface{}{
			"servers": []interface{}{map[string]interface{}{
				"address": host, "port": port, "method": method, "password": uuid,
			}},
		}
	default:
		// Xray 出站不支持 anytls/hysteria2/naive 等协议
		return nil
	}
	return outbound
}
