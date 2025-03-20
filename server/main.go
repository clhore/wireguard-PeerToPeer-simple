package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
)

type peerInfo struct {
	ID            string
	Token         string
	PeerPublicKey string
	TCPConn       net.Conn     // TCP 443
	UDPAddr       *net.UDPAddr // UDP 5000
}

var allowedClients = map[string]string{
	"PeerA": "tokendeaccesoPeerA",
	"PeerB": "tokendeaccesoPeerB",
}

// peers guarda los peers registrados (ID -> *peerInfo)
var peers = make(map[string]*peerInfo)
var peersMutex sync.Mutex

// connections define las conexiones que deben establecerse (por simplicidad, 2 peers).
var connections = [][]string{
	{"PeerA", "PeerB"},
}

func main() {
	// TCP 443, servidor de autenticación
	go startTCPAuthServer()
	// UDP 5000, servidor de NAT traversal
	go startUDPTraversalServer()
	// Mantener vivo
	select {}
}

func startTCPAuthServer() {
	ln, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatalf("Error iniciando servidor TCP en 443: %v", err)
	}
	defer ln.Close()
	log.Println("Servidor TCP (auth) escuchando en :443")
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("Error aceptando conexión TCP:", err)
			continue
		}
		go handleTCPAuth(conn)
	}
}

func handleTCPAuth(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	// Esperar un mensaje "auth <ID> <token> <publicKey>"
	// Por ejemplo: "auth PeerA tokendeaccesoPeerA publicKeyPeerABase64"
	line, err := reader.ReadString('\n')
	if err != nil {
		log.Println("Error leyendo auth:", err)
		return
	}
	line = strings.TrimSpace(line)
	parts := strings.Split(line, " ")
	if len(parts) < 4 || parts[0] != "auth" {
		log.Printf("Mensaje de auth inválido: %s\n", line)
		return
	}
	peerID, token, wgPeerPublicKey := parts[1], parts[2], parts[3]
	// Validar token
	expected, ok := allowedClients[peerID]
	if !ok || expected != token {
		log.Printf("Peer %s no autorizado. Token: %s\n", peerID, token)
		return
	}
	peersMutex.Lock()
	peers[peerID] = &peerInfo{
		ID:            peerID,
		Token:         token,
		PeerPublicKey: wgPeerPublicKey,
		TCPConn:       conn,
		UDPAddr:       nil,
	}
	log.Printf("Autenticado peer %s desde %s\n", peerID, conn.RemoteAddr().String())
	// Verificar si se puede notificar que ambos peers están listos para NAT traversal
	checkAndNotifyAuth()
	peersMutex.Unlock()
	// Mantener la conexión abierta (si se quisiera updates, etc.)
	// En este ejemplo, no hacemos nada más y esperamos.
	for {
		msg, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("Conexión cerrada con %s: %v\n", peerID, err)
			break
		}
		msg = strings.TrimSpace(msg)
		// Podríamos manejar "update" u otros comandos
		log.Printf("Mensaje TCP de %s: %s\n", peerID, msg)
	}
}

// checkAndNotifyAuth notifica a los peers que pueden proceder con NAT traversal
func checkAndNotifyAuth() {
	for _, pair := range connections {
		if len(pair) < 2 {
			continue
		}
		p1, p2 := pair[0], pair[1]
		info1, ok1 := peers[p1]
		info2, ok2 := peers[p2]
		if ok1 && ok2 {
			// Notificar a cada peer por TCP que ambos están listos
			msg := "auth_ok\n"
			if info1.TCPConn != nil {
				info1.TCPConn.Write([]byte(msg))
			}
			if info2.TCPConn != nil {
				info2.TCPConn.Write([]byte(msg))
			}
			log.Printf("Notificado a %s y %s que pueden hacer NAT traversal.\n", p1, p2)
		}
	}
}

func startUDPTraversalServer() {
	addr, err := net.ResolveUDPAddr("udp", ":5000")
	if err != nil {
		log.Fatalf("Error resolviendo UDP en 5000: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("Error escuchando UDP en 5000: %v", err)
	}
	defer conn.Close()
	log.Println("Servidor UDP (NAT) escuchando en :5000")
	buffer := make([]byte, 1024)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Println("Error leyendo UDP:", err)
			continue
		}
		msg := strings.TrimSpace(string(buffer[:n]))
		log.Printf("[UDP] Mensaje de %s: %s\n", clientAddr.String(), msg)
		processUDPMessage(conn, msg, clientAddr)
	}
}

func processUDPMessage(conn *net.UDPConn, msg string, clientAddr *net.UDPAddr) {
	parts := strings.Split(msg, " ")
	if len(parts) < 2 {
		return
	}
	cmd := parts[0]
	name := parts[1]
	peersMutex.Lock()
	defer peersMutex.Unlock()
	switch cmd {
	case "register":
		// Marcar la dirección UDP del peer
		if p, ok := peers[name]; ok {
			p.UDPAddr = clientAddr
			log.Printf("Peer %s registrado en NAT con %s\n", name, clientAddr.String())
		} else {
			log.Printf("Peer %s no está autenticado o no existe.\n", name)
			return
		}
		// Si hay al menos otro peer, intercambiar direcciones
		if len(peers) >= 2 {
			// Para simplificar, tomamos los últimos 2
			var peerNames []string
			for k := range peers {
				peerNames = append(peerNames, k)
			}
			if len(peerNames) >= 2 {
				p1 := peerNames[len(peerNames)-1]
				p2 := peerNames[len(peerNames)-2]
				// Enviar a p1 la dirección de p2
				if peers[p2].UDPAddr != nil && peers[p1].UDPAddr != nil {
					addrP2 := peers[p2].UDPAddr.String()
					publicKeyP2 := peers[p2].PeerPublicKey
					msgP1 := fmt.Sprintf("connect %s %s %s", p2, addrP2, publicKeyP2)
					conn.WriteToUDP([]byte(msgP1), peers[p1].UDPAddr)
					// Enviar a p2 la dirección de p1
					addrP1 := peers[p1].UDPAddr.String()
					publicKeyP1 := peers[p1].PeerPublicKey
					msgP2 := fmt.Sprintf("connect %s %s %s", p1, addrP1, publicKeyP1)
					conn.WriteToUDP([]byte(msgP2), peers[p2].UDPAddr)
					log.Printf("Intercambiadas direcciones NAT entre %s y %s\n", p1, p2)
				}
			}
		}
	case "update":
		// Actualizar la dirección UDP (si cambió)
		if p, ok := peers[name]; ok {
			p.UDPAddr = clientAddr
			log.Printf("Peer %s actualizó su dirección a %s\n", name, clientAddr.String())
		}
	case "SYN":
		// Mensaje de "SYN" de un peer
		log.Printf("-> Recibido SYN desde %s\n", clientAddr.String())
		// Responder con "SYN-ACK"
		conn.WriteToUDP([]byte("SYN-ACK"), clientAddr)
	case "SYN-ACK":
		// Respuesta a "SYN"
		log.Printf("-> Recibido SYN-ACK desde %s\n", clientAddr.String())
	default:
		log.Printf("Comando desconocido: %s\n", msg)
	}
}
