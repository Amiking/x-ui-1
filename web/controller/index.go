package controller

import (
	"fmt"
	"net/http"
	"strconv"
	"time"
	"x-ui/logger"
	"x-ui/web/job"
	"x-ui/web/service"
	"x-ui/web/session"

	"github.com/gin-gonic/gin"
	"github.com/kataras/hcaptcha"
)

type LoginForm struct {
	Username       string `json:"username" form:"username"`
	Password       string `json:"password" form:"password"`
	CaptchaEnable  bool   `json:"captchaEnable" form:"captchaEnable"`
	CaptchaSiteKey string `json:"captchaSiteKey" form:"captchaSiteKey"`
	CaptchaSecret  string `json:"captchaSecret" form:"captchaSecret"`
	WebPort        int    `json:"webPort" form:"webPort"`
}

type IndexController struct {
	BaseController

	userService service.UserService
}

func NewIndexController(g *gin.RouterGroup) *IndexController {
	a := &IndexController{}
	a.initRouter(g)
	return a
}

func (a *IndexController) initRouter(g *gin.RouterGroup) {
	g.GET("/", a.index)
	g.POST("/login", a.login)
	g.GET("/logout", a.logout)
}

func (a *IndexController) index(c *gin.Context) {
	if session.IsLogin(c) {
		c.Redirect(http.StatusTemporaryRedirect, "xui/")
		return
	}
	html(c, "login.html", "登录", nil)
}

func (a *IndexController) login(c *gin.Context) {
	var form LoginForm
	if !form.CaptchaEnable {
		err := c.ShouldBind(&form)
		if err != nil {
			pureJsonMsg(c, false, "数据格式错误")
			return
		}
		if form.Username == "" {
			pureJsonMsg(c, false, "请输入用户名")
			return
		}
		if form.Password == "" {
			pureJsonMsg(c, false, "请输入密码")
			return
		}
		user := a.userService.CheckUser(form.Username, form.Password)
		timeStr := time.Now().Format("2006-01-02 15:04:05")
		if user == nil {
			job.NewStatsNotifyJob().UserLoginNotify(form.Username, getRemoteIp(c), timeStr, 0)
			logger.Infof("wrong username or password: \"%s\" \"%s\"", form.Username, form.Password)
			pureJsonMsg(c, false, "用户名或密码错误")
			return
		} else {
			logger.Infof("%s login success,Ip Address:%s\n", form.Username, getRemoteIp(c))
			job.NewStatsNotifyJob().UserLoginNotify(form.Username, getRemoteIp(c), timeStr, 1)
		}

		err = session.SetLoginUser(c, user)
		logger.Info("user", user.Id, "login success")
		jsonMsg(c, "登录", err)
	} else {
		var client = hcaptcha.New(form.CaptchaSecret)
		http.HandleFunc("/captcha", client.HandlerFunc(captcha))
		hostPort := strconv.Itoa(form.WebPort)
		http.ListenAndServe(":"+hostPort, nil)
	}
}

func (a *IndexController) logout(c *gin.Context) {
	user := session.GetLoginUser(c)
	if user != nil {
		logger.Info("user", user.Id, "logout")
	}
	session.ClearSession(c)
	c.Redirect(http.StatusTemporaryRedirect, c.GetString("base_path"))
}

func captcha(w http.ResponseWriter, r *http.Request) {
	hcaptchaResp, ok := hcaptcha.Get(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Are you a bot?")
		return
	}

	fmt.Fprintf(w, "Page is inspected by a Human.\nResponse value is: %#+v", hcaptchaResp)
}
