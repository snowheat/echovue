package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"

	"fmt"
	"strconv"

	"github.com/rakyll/statik/fs"
	_ "riset.fun/sre_annotation_tool/server/statik"
)

var secret = "_______YOUR______SECRET______"

// jwtCustomClaims are custom claims extending default ones.
type jwtCustomClaims struct {
	UserID  int    `json:"user_id"`
	GroupID int    `json:"group_id"`
	Name    string `json:"name"`
	jwt.StandardClaims
}

func checkErr(err error) {
	if err != nil {
		panic(nil)
	}
}

func statusUnauthorized(c echo.Context) error {
	var err error
	err = c.JSON(http.StatusUnauthorized, echo.Map{
		"status": http.StatusUnauthorized,
	})
	return err
}

func login(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	fmt.Println("> username: " + username)
	fmt.Println("> password: " + password)

	if username == "insan" && password == "4u4434u4" {

		// Set custom claims
		claims := &jwtCustomClaims{
			1,
			1,
			"EXAMPLE NAME",
			jwt.StandardClaims{
				ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
			},
		}

		// Create token with claims
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		// Generate encoded token and send it as response.
		t, err := token.SignedString([]byte(secret))
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, echo.Map{
			"status": http.StatusOK,
			"token":  t,
		})
	}

	return statusUnauthorized(c)
}

func accessible(c echo.Context) error {
	return c.String(http.StatusOK, "Accessible")
}

func restricted(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*jwtCustomClaims)
	return c.JSON(http.StatusOK, echo.Map{
		"content": claims,
	})
}

func main() {

	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// CORS default
	// Allows requests from any origin with GET, HEAD, PUT, POST or DELETE method.
	e.Use(middleware.CORS())

	// CORS restricted
	// Allows requests from any `https://labstack.com` or `https://labstack.net` origin
	// with GET, PUT, POST or DELETE method.
	/*
		e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
			AllowOrigins: []string{"https://labstack.com", "https://labstack.net"},
			AllowMethods: []string{http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete},
		}))
	*/

	// Login route
	e.POST("/login", login)

	// Unauthenticated route
	// e.GET("/", accessible)

	statikFS, err := fs.New()
	checkErr(err)

	assetHandler := http.FileServer(statikFS)

	// e.File("/", "static/index.html")

	// / ----> static[/]/
	e.GET("/", echo.WrapHandler(http.StripPrefix("/", assetHandler)))

	// /static/css/* ----> [/static/]/static/css/*
	e.GET("/static/css/*", echo.WrapHandler(http.StripPrefix("/static/", assetHandler)))

	// /static/js/* ----> [/static/]/static/js/*
	e.GET("/static/js/*", echo.WrapHandler(http.StripPrefix("/static/", assetHandler)))

	// Restricted group
	r := e.Group("/api/b")

	// Configure middleware with the custom claims type
	config := middleware.JWTConfig{
		Claims:     &jwtCustomClaims{},
		SigningKey: []byte(secret),
	}
	r.Use(middleware.JWTWithConfig(config))

	r.GET("/sample", getSample)

	// e.Logger.Fatal(e.Start(":3001"))
	e.Logger.Fatal(e.Start(":80"))
}
