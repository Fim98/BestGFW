package controllers

import (
	"encoding/json"
	"freegfw/database"
	"freegfw/models"
	"freegfw/services"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func GetConfigs(c *gin.Context) {
	var serverSettings models.Setting
	database.DB.Where("key = ?", "server").Limit(1).Find(&serverSettings)

	var titleSettings models.Setting
	database.DB.Where("key = ?", "title").Limit(1).Find(&titleSettings)
	title := "FreeGFW"
	if len(titleSettings.Value) > 0 {
		json.Unmarshal(titleSettings.Value, &title)
	}

	var ipSettings models.Setting
	database.DB.Where("key = ?", "ip").Limit(1).Find(&ipSettings)
	var ip string
	if len(ipSettings.Value) > 0 {
		json.Unmarshal(ipSettings.Value, &ip)
	}

	var ipv6Settings models.Setting
	database.DB.Where("key = ?", "ipv6").Limit(1).Find(&ipv6Settings)
	var ipv6 string
	if len(ipv6Settings.Value) > 0 {
		json.Unmarshal(ipv6Settings.Value, &ipv6)
	}

	var passSettings models.Setting
	database.DB.Where("key = ?", "password").Limit(1).Find(&passSettings)
	hasPassword := len(passSettings.Value) > 0

	var sslSettings models.Setting
	database.DB.Where("key = ?", "letsencrypt_domain").Limit(1).Find(&sslSettings)
	ssl := len(sslSettings.Value) > 0

	core := services.NewCoreService()

	// serverSettings.Value is RawMessage (text/string in DB), we might need to unmarshal to object if frontend expects object
	var serverObj interface{}
	if len(serverSettings.Value) > 0 {
		json.Unmarshal(serverSettings.Value, &serverObj)
	}

	var warpEnabledSettings models.Setting
	database.DB.Where("key = ?", "warp_enabled").Limit(1).Find(&warpEnabledSettings)
	warpEnabled := false
	if len(warpEnabledSettings.Value) > 0 {
		json.Unmarshal(warpEnabledSettings.Value, &warpEnabled)
	}

	var bindDomainSettings models.Setting
	database.DB.Where("key = ?", "bind_domain").Limit(1).Find(&bindDomainSettings)
	var bindDomain string
	if len(bindDomainSettings.Value) > 0 {
		json.Unmarshal(bindDomainSettings.Value, &bindDomain)
	}

	var preferredAddrSettings models.Setting
	database.DB.Where("key = ?", "preferred_address").Limit(1).Find(&preferredAddrSettings)
	var preferredAddress string
	if len(preferredAddrSettings.Value) > 0 {
		json.Unmarshal(preferredAddrSettings.Value, &preferredAddress)
	}

	var chainLinkID *uint
	var chainSetting models.Setting
	database.DB.Where("key = ?", "chain_link_id").Limit(1).Find(&chainSetting)
	if len(chainSetting.Value) > 0 {
		json.Unmarshal(chainSetting.Value, &chainLinkID)
	}

	var chainPort int
	var chainPortSetting models.Setting
	database.DB.Where("key = ?", "chain_port").Limit(1).Find(&chainPortSetting)
	if len(chainPortSetting.Value) > 0 {
		json.Unmarshal(chainPortSetting.Value, &chainPort)
	}
	if chainPort <= 0 {
		chainPort = services.GetChainPort()
	}

	c.JSON(http.StatusOK, gin.H{
		"server":            serverObj,
		"title":             title,
		"inited":            len(serverSettings.Value) > 0,
		"running":           core.IsRunning(),
		"ip":                ip,
		"ipv6":              ipv6,
		"has_password":      hasPassword,
		"ssl":               ssl,
		"warp_enabled":      warpEnabled,
		"bind_domain":       bindDomain,
		"preferred_address": preferredAddress,
		"chain_link_id":     chainLinkID,
		"chain_port":        chainPort,
	})
}

func UpdateConfig(c *gin.Context) {
	var payload map[string]interface{}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	allowed := []string{"username", "password", "title", "warp_enabled", "bind_domain", "preferred_address", "chain_link_id", "chain_port"}
	for _, key := range allowed {
		if val, ok := payload[key]; ok {
			if key == "bind_domain" || key == "preferred_address" {
				if vs, isStr := val.(string); isStr {
					val = normalizeHost(vs)
				}
			}
			jsonVal, _ := json.Marshal(val) // Handle null/empty logic
			var s models.Setting
			if database.DB.Where("key = ?", key).Limit(1).Find(&s).RowsAffected == 0 {
				s = models.Setting{Key: key}
			}
			if val == nil || val == "" {
				s.Value = nil
			} else {
				s.Value = models.JSON(jsonVal)
			}
			database.DB.Save(&s)
		}
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// normalizeHost 清理用户输入的域名/地址：去掉协议、路径、查询串和端口
func normalizeHost(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return s
}

func ReloadConfig(c *gin.Context) {
	core := services.NewCoreService()
	core.Refresh()
	core.Start()
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func ResetConfig(c *gin.Context) {
	// Delete settings except letsencrypt
	database.DB.Where("key NOT IN ?", []string{"letsencrypt_domain", "letsencrypt_email", "letsencrypt_updated_at"}).Delete(&models.Setting{})
	// Truncate Users
	database.DB.Exec("DELETE FROM users") // SQLite doesn't have TRUNCATE

	core := services.NewCoreService()
	core.Reset()
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func SetTitle(c *gin.Context) {
	var payload struct {
		Title string `json:"title"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var s models.Setting
	if database.DB.Where("key = ?", "title").Limit(1).Find(&s).RowsAffected == 0 {
		s = models.Setting{Key: "title"}
	}
	val, _ := json.Marshal(payload.Title)
	s.Value = models.JSON(val)
	database.DB.Save(&s)

	c.JSON(http.StatusOK, gin.H{"success": true})
}
