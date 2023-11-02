package main

import (
	"crypto/rand"
	"embed"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"html/template"
	"net/http"
	"os"
	"strconv"
)

type User struct {
	Id    string
	Money int64
	Items map[string]int64
}

type Product struct {
	Name  string
	Price int64
}

var users map[string]*User

var products []*Product

//go:embed public
var fs embed.FS

func init() {
	users = make(map[string]*User)
	products = []*Product{
		{Name: "Apple", Price: 10},
		{Name: "Banana", Price: 50},
		{Name: "Orange", Price: 100},
		{Name: "Flag", Price: 999999999},
	}
}

func IndexHandler(c *gin.Context) {
	c.HTML(200, "index.html", gin.H{})
}

func InfoHandler(c *gin.Context) {
	s := sessions.Default(c)

	if s.Get("id") == nil {
		u := uuid.New().String()
		users[u] = &User{Id: u, Money: 100, Items: make(map[string]int64)}
		s.Set("id", u)
		s.Save()
	}

	user := users[s.Get("id").(string)]
	c.JSON(200, gin.H{
		"user": user,
	})
}

func ResetHandler(c *gin.Context) {
	s := sessions.Default(c)
	s.Clear()

	u := uuid.New().String()
	users[u] = &User{Id: u, Money: 100, Items: make(map[string]int64)}
	s.Set("id", u)
	s.Save()

	c.JSON(200, gin.H{
		"message": "Reset success",
	})
}

func BuyHandler(c *gin.Context) {
	s := sessions.Default(c)
	user := users[s.Get("id").(string)]

	data := make(map[string]interface{})
	c.ShouldBindJSON(&data)

	var product *Product

	for _, v := range products {
		if data["name"] == v.Name {
			product = v
			break
		}
	}

	if product == nil {
		c.JSON(200, gin.H{
			"message": "No such product",
		})
		return
	}

	n, _ := strconv.Atoi(data["num"].(string))

	if n < 0 {
		c.JSON(200, gin.H{
			"message": "Product num can't be negative",
		})
		return
	}

	if user.Money >= product.Price*int64(n) {
		user.Money -= product.Price * int64(n)
		user.Items[product.Name] += int64(n)
		c.JSON(200, gin.H{
			"message": fmt.Sprintf("Buy %v * %v success", product.Name, n),
		})
	} else {
		c.JSON(200, gin.H{
			"message": "You don't have enough money",
		})
	}
}

func SellHandler(c *gin.Context) {
	s := sessions.Default(c)
	user := users[s.Get("id").(string)]

	data := make(map[string]interface{})
	c.ShouldBindJSON(&data)

	var product *Product

	for _, v := range products {
		if data["name"] == v.Name {
			product = v
			break
		}
	}

	if product == nil {
		c.JSON(200, gin.H{
			"message": "No such product",
		})
		return
	}

	count := user.Items[data["name"].(string)]
	n, _ := strconv.Atoi(data["num"].(string))

	if n < 0 {
		c.JSON(200, gin.H{
			"message": "Product num can't be negative",
		})
		return
	}

	if count >= int64(n) {
		user.Money += product.Price * int64(n)
		user.Items[product.Name] -= int64(n)
		c.JSON(200, gin.H{
			"message": fmt.Sprintf("Sell %v * %v success", product.Name, n),
		})
	} else {
		c.JSON(200, gin.H{
			"message": "You don't have enough product",
		})
	}
}

func FlagHandler(c *gin.Context) {
	s := sessions.Default(c)
	user := users[s.Get("id").(string)]

	v, ok := user.Items["Flag"]
	if !ok || v <= 0 {
		c.JSON(200, gin.H{
			"message": "You must buy <code>flag</code> first",
		})
		return
	}

	flag, _ := os.ReadFile("/flag")
	c.JSON(200, gin.H{
		"message": fmt.Sprintf("Here is your flag: <code>%s</code>", string(flag)),
	})
}

func main() {
	secret := make([]byte, 16)
	rand.Read(secret)

	tpl, _ := template.ParseFS(fs, "public/index.html")
	store := cookie.NewStore(secret)

	r := gin.Default()
	r.SetHTMLTemplate(tpl)
	r.Use(sessions.Sessions("gosession", store))

	r.GET("/", IndexHandler)

	api := r.Group("/api")
	{
		api.GET("/info", InfoHandler)
		api.POST("/buy", BuyHandler)
		api.POST("/sell", SellHandler)
		api.GET("/flag", FlagHandler)
		api.GET("/reset", ResetHandler)
	}

	r.StaticFileFS("/static/main.js", "public/main.js", http.FS(fs))
	r.StaticFileFS("/static/simple.css", "public/simple.css", http.FS(fs))

	r.Run(":8000")
}
