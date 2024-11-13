package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/keyauth"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

var secretKey = []byte("segredo-muito-bom")

var db *gorm.DB

type Log_wp_interation struct {
	Id      int
	Message string `sql:"type:varchar(500);"`
}

func validateAPIKey(c *fiber.Ctx, key string) (bool, error) {
	hashedAPIKey := sha256.Sum256([]byte(secretKey))

	t := new(Log_wp_interation)

	t.Message = key

	db.Create(&t)

	chave, err := hex.DecodeString(key)

	if err != nil {
		return false, err
	}
	//fmt.Printf("%x", chave)

	if subtle.ConstantTimeCompare(hashedAPIKey[:], chave[:]) == 1 {
		return true, nil
	}
	return false, keyauth.ErrMissingOrMalformedAPIKey
}

func main() {
	var err error
	/*file, err := os.OpenFile("./wp.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(file)*/

	db, err = gorm.Open("postgres", "host=dpg-csp3urqj1k6c73ch17g0-a user=dbwp_user dbname=dbwp sslmode=disable password=vmUXr7elwq4ZFjwkQKya7tH11JAhpWw4")
	if err != nil {
		log.Panic("failed to connect database: " + err.Error())
	}
	db.SingularTable(true)
	db.AutoMigrate(&Log_wp_interation{})

	/*db, err := gorm.Open("sqlite", "./db/data.db")
	if err != nil {
		log.Fatal(err)
	}
	db.SingularTable(true)*/

	app := fiber.New()
	/*app.Use(keyauth.New(keyauth.Config{KeyLookup: "header:" + fiber.HeaderAuthorization,
		AuthScheme: "Bearer",
		Validator:  validateAPIKey,
	}))*/
	app.Use(keyauth.New(keyauth.Config{KeyLookup: "query:hub.verify_token",
		Validator: validateAPIKey,
	}))
	app.Get("/", func(c *fiber.Ctx) error {
		err := c.Status(200).SendString(c.Query("hub.challenge"))
		res := new(Log_wp_interation)
		req := c.Body()
		res.Message = string(req)
		db.Create(&res)
		return err
	})

	app.Post("/", func(c *fiber.Ctx) error {
		res := new(Log_wp_interation)
		req := c.Body()
		//token := c.Get("Authorization")
		log.Println(string(req))
		res.Message = string(req)
		/*err := json.Unmarshal([]byte(req), &res)
		if err != nil {
			fmt.Println("Erro:", err.Error())
			return err
		}*/
		db.Create(&res)
		return nil
	})

	app.Post("/webhooks", func(c *fiber.Ctx) error {
		res := new(Log_wp_interation)
		req := c.Body()
		//token := c.Get("Authorization")
		log.Println(string(req))
		res.Message = string(req)
		/*err := json.Unmarshal([]byte(req), &res)
		if err != nil {
			fmt.Println("Erro:", err.Error())
			return err
		}*/
		db.Create(&res)
		return nil
	})

	log.Fatal(app.Listen(":443"))

}
