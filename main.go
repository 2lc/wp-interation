package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/keyauth"
	"github.com/jinzhu/gorm"
	_ "modernc.org/sqlite"
)

var secretKey = []byte("segredo-muito-bom")

type transaction struct {
	ID    string `json:"id"`
	Quote string `json:"quote"`
}

type Pcp_estacao_eton struct {
	Id         int
	Estacao    int
	Node       int
	Usuario    string
	Terminal   int
	Pedido     string
	Id_costura string
	Pacote     string
	Tempo      string
}

func validateAPIKey(c *fiber.Ctx, key string) (bool, error) {
	hashedAPIKey := sha256.Sum256([]byte(secretKey))

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
	file, err := os.OpenFile("./wp.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(file)

	db, err := gorm.Open("sqlite", "./db/data.db")
	if err != nil {
		log.Fatal(err)
	}
	db.SingularTable(true)

	app := fiber.New()
	app.Use(keyauth.New(keyauth.Config{KeyLookup: "header:" + fiber.HeaderAuthorization,
		AuthScheme: "Bearer",
		Validator:  validateAPIKey,
	}))
	app.Get("/", func(c *fiber.Ctx) error {
		err := c.Status(200).SendString("And the API is UP!")
		return err
	})

	app.Post("/", func(c *fiber.Ctx) error {
		//res := new(Pcp_estacao_eton)
		req := c.Body()
		//token := c.Get("Authorization")
		log.Println(string(req))
		/*err := json.Unmarshal([]byte(req), &res)
		if err != nil {
			fmt.Println("Erro:", err.Error())
			return err
		}
		db.Create(&res)*/
		return nil
	})

	log.Fatal(app.Listen(":443"))

}
