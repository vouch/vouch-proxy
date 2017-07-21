package transciever

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/bnfinet/lasso/pkg/model"
	"github.com/bnfinet/lasso/pkg/structs"

	log "github.com/Sirupsen/logrus"
	"github.com/mitchellh/mapstructure"

	"github.com/gorilla/websocket"
)

// based on
// https://github.com/gorilla/websocket/blob/master/examples/chat/client.go

var allConns map[*websocket.Conn]bool

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second
	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second
	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10
	// Maximum message size allowed from peer.
	maxMessageSize = 512
)

var (
	newline = []byte{'\n'}
	space   = []byte{' '}
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// Client is a middleman between the websocket connection and the hub.
type Client struct {
	hub *Hub

	// The websocket connection.
	conn *websocket.Conn

	// Buffered channel of outbound messages.
	send chan []byte
}

type pkg struct {
	T string      `json:"type"`
	D interface{} `json:"data"`
}

// readPump pumps messages from the websocket connection to the hub.
//
// The application runs readPump in a per-connection goroutine. The application
// ensures that there is at most one reader on a connection by executing all
// reads from this goroutine.
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error { c.conn.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	for {
		var p pkg
		err := c.conn.ReadJSON(&p)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway) {
				log.Errorf("error: %v", err)
			}
			break
		}
		log.Infof("ws message: %v", p)

		// _, message, err := c.conn.ReadMessage()
		// if err != nil {
		// 	if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway) {
		// 		log.Errorf("error: %v", err)
		// 	}
		// 	break
		// }
		// message = bytes.TrimSpace(bytes.Replace(message, newline, space, -1))
		// json.Unmarshal(message, &p)
		// log.Infof("ws message: %s, %v", message, p)
		if p.T == "getusers" {
			c.getUsers()
		} else if p.T == "getsites" {
			c.getSites()
		} else if p.T == "getteams" {
			c.getTeams()
		} else if p.T == "updateteam" {
			c.updateTeam(p.D)
		}
		// c.hub.broadcast <- []byte(p)
	}
}

func (c *Client) updateTeam(data interface{}) {
	log.Debugf("creating team from %v", data)

	t := structs.Team{}
	mapstructure.Decode(data, &t)
	// if err := json.Unmarshal(data, &t); err != nil {
	// 	log.Error(err)
	// 	return
	// }
	model.PutTeam(t)
	c.getTeams()
}

// writePump pumps messages from the hub to the websocket connection.
//
// A goroutine running writePump is started for each connection. The
// application ensures that there is at most one writer to a connection by
// executing all writes from this goroutine.
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// The hub closed the channel.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Add queued chat messages to the current websocket message.
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write(newline)
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
				return
			}
		}
	}
}

func (c *Client) getUsers() {
	var users []structs.User
	model.AllUsers(&users)
	log.Debugf("shipping users %v", users)
	c.shipping("users", users)
}

func (c *Client) getSites() {
	var sites []structs.Site
	model.AllSites(&sites)
	log.Debugf("shipping sites %v", sites)
	c.shipping("sites", sites)
}

func (c *Client) getTeams() {
	var teams []structs.Team
	model.AllTeams(&teams)
	log.Debugf("shipping teams %v", teams)
	c.shipping("teams", teams)
}

func (c *Client) shipping(t string, v interface{}) {
	// d, _ := json.Marshal(v)
	p := &pkg{t, v}
	j, err := json.Marshal(p)
	if err != nil {
		log.Error(err)
	}
	c.send <- j
}

// serveWs handles websocket requests from the peer.
func serveWs(hub *Hub, w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	client := &Client{hub: hub, conn: conn, send: make(chan []byte, 256)}
	client.hub.register <- client
	go client.writePump()
	client.readPump()
}

func Echo(conn *websocket.Conn) error {
	messageType, r, err := conn.NextReader()
	if err != nil {
		return err
	}
	w, err := conn.NextWriter(messageType)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, r); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return nil
}

func readLoop(conn *websocket.Conn) {
	for {
		if _, _, err := conn.NextReader(); err != nil {
			conn.Close()
			break
		}
	}
}
