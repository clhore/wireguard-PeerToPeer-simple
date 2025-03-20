package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

const (
	serverPublicIP = "<IP_Publica_Servidor>"
	serverTCP      = serverPublicIP + ":443"  // Servidor autenticación TCP
	serverUDP      = serverPublicIP + ":5000" // Servidor NAT traversal UDP
	localPort      = "51820"                  // Puerto NAT traversal y WireGuard
)

func main() {
	// Se esperan los siguientes argumentos:
	// <peerID> <token> <wgPrivateKey> <wgAddress> <allowedIPs>
	if len(os.Args) < 6 {
		fmt.Println("Uso: go run client.go <peerID> <token> <wgPrivateKey> <wgAddress> <allowedIPs>")
		return
	}
	peerID := os.Args[1]
	token := os.Args[2]
	wgPrivateKey := os.Args[3] // Clave privada en base64
	wgAddress := os.Args[4]    // Ej: "10.0.0.1/24"
	allowedIPs := os.Args[5]   // Ej: "10.0.0.2/32"

	// Derivar la clave pública local a partir de la clave privada.
	localPublicKey := derivePublicKey(wgPrivateKey)
	fmt.Printf("Clave pública local derivada: %s\n", localPublicKey)

	// Fase 1: Autenticación por TCP en el puerto 443
	err := authenticateTCP(peerID, token, localPublicKey)
	if err != nil {
		log.Fatalf("Error en autenticación TCP: %v", err)
	}

	// Fase 2: NAT traversal vía UDP en el puerto 5000 usando puerto local 51820.
	externalMapping, remotePeerPubKey, err := startNATTraversal(peerID)
	if err != nil {
		log.Fatalf("Error en NAT traversal: %v", err)
	}

	fmt.Printf("Mapeo NAT propio detectado: %s\n", externalMapping)
	fmt.Printf("Clave pública del otro peer: %s\n", remotePeerPubKey)

	// Fase 3: Levantar el túnel P2P con WireGuard.
	err = startWireGuard(peerID, localPort, wgPrivateKey, wgAddress, remotePeerPubKey, externalMapping, allowedIPs)
	if err != nil {
		log.Fatalf("Error iniciando WireGuard: %v", err)
	}
	fmt.Println("Túnel WireGuard levantado correctamente.")

	// Mantener el proceso vivo hasta que se escriba "exit" en consola.
	consoleReader := bufio.NewReader(os.Stdin)
	fmt.Println("Escribe 'exit' para terminar")
	for {
		line, _ := consoleReader.ReadString('\n')
		if strings.TrimSpace(line) == "exit" {
			break
		}
	}
}

// authenticateTCP realiza la autenticación con el servidor en el puerto 443.
// Envía "auth <peerID> <token>" y espera "auth_ok".
func authenticateTCP(peerID, token, localPublicKey string) error {
	conn, err := net.Dial("tcp", serverTCP)
	if err != nil {
		return fmt.Errorf("no se pudo conectar al servidor TCP: %v", err)
	}
	defer conn.Close()

	msg := fmt.Sprintf("auth %s %s %s\n", peerID, token, localPublicKey)
	_, err = conn.Write([]byte(msg))
	if err != nil {
		return fmt.Errorf("error enviando auth: %v", err)
	}
	fmt.Printf("Mensaje de autenticación enviado a %s\n", serverTCP)

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error leyendo respuesta auth: %v", err)
	}
	line = strings.TrimSpace(line)
	if line != "auth_ok" {
		return fmt.Errorf("respuesta inesperada del servidor: %s", line)
	}
	fmt.Println("Autenticación exitosa. Procediendo con NAT traversal.")
	return nil
}

// startNATTraversal abre un socket UDP en el puerto 51820, se registra con el servidor UDP y
// espera el mensaje "connect <peerID> <peerMapping> <wgPeerPublicKey>".
// Una vez recibido, realiza un hole punching bidireccional y retorna la info del otro peer.
func startNATTraversal(peerID string) (string, string, error) {
	localAddr, err := net.ResolveUDPAddr("udp", ":"+localPort)
	if err != nil {
		return "", "", fmt.Errorf("error resolviendo dirección local UDP: %v", err)
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return "", "", fmt.Errorf("error abriendo socket UDP en %s: %v", localPort, err)
	}
	// No defer conn.Close() aún; se cerrará cuando terminemos.

	serverAddr, err := net.ResolveUDPAddr("udp", serverUDP)
	if err != nil {
		conn.Close()
		return "", "", fmt.Errorf("error resolviendo dirección del servidor UDP: %v", err)
	}

	// Enviar registro por UDP: "register <peerID>"
	regMsg := fmt.Sprintf("register %s", peerID)
	_, err = conn.WriteToUDP([]byte(regMsg), serverAddr)
	if err != nil {
		conn.Close()
		return "", "", fmt.Errorf("error enviando registro UDP: %v", err)
	}
	fmt.Printf("Enviado registro UDP: %q\n", regMsg)

	// Esperar el mensaje "connect <peerID> <peerMapping> <wgPeerPublicKey>"
	timeout := time.Now().Add(30 * time.Second)
	var natMapping, remotePeerPubKey string

readLoop:
	for {
		if time.Now().After(timeout) {
			conn.Close()
			return "", "", fmt.Errorf("timeout esperando información de conexión NAT")
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1024)
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("Error leyendo UDP: %v", err)
			continue
		}
		msg := strings.TrimSpace(string(buf[:n]))
		fmt.Printf("[UDP] Recibido de %s: %s\n", addr.String(), msg)

		parts := strings.Split(msg, " ")
		if len(parts) >= 3 && parts[0] == "connect" {
			// "connect <peerID> <peerMapping> <wgPeerPublicKey>"
			natMapping = parts[2]
			if len(parts) >= 4 {
				remotePeerPubKey = parts[3]
			} else {
				remotePeerPubKey = ""
			}
			// Iniciar hole punching bidireccional
			otherUDPAddr, err := net.ResolveUDPAddr("udp", natMapping)
			if err != nil {
				log.Printf("Error resolviendo dirección del peer: %v", err)
				continue
			}
			fmt.Printf("Orden de conectar con %s, mapping: %s\n", parts[1], natMapping)

			err = holePunchBidirectional(conn, otherUDPAddr, 15*time.Second)
			if err != nil {
				log.Printf("Error en hole punching: %v", err)
			} else {
				fmt.Println("NAT traversal completado satisfactoriamente.")
			}
			break readLoop
		}
		// Si no es "connect", ignoramos o manejamos SYN/SYN-ACK aquí (ver holePunchBidirectional).
	}
	conn.Close()
	return natMapping, remotePeerPubKey, nil
}

// holePunchBidirectional implementa un intercambio de "SYN" y "SYN-ACK" en ambos sentidos.
// Hasta que no recibamos "SYN-ACK" del otro peer, no consideramos el NAT traversal completado.
func holePunchBidirectional(conn *net.UDPConn, peerAddr *net.UDPAddr, overallTimeout time.Duration) error {
	done := make(chan bool, 1)
	stop := make(chan bool, 1)

	// 1) Goroutine para ENVIAR "SYN" repetidamente
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				_, err := conn.WriteToUDP([]byte("SYN"), peerAddr)
				if err != nil {
					fmt.Printf("Error enviando SYN a %s: %v\n", peerAddr, err)
					return
				}
				fmt.Printf("Enviado SYN a %s\n", peerAddr.String())
			}
		}
	}()

	// 2) Goroutine para ESCUCHAR "SYN" y "SYN-ACK"
	go func() {
		buf := make([]byte, 1024)
		for {
			select {
			case <-stop:
				return
			default:
			}
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				// Timeout => seguimos
				continue
			}
			msg := strings.TrimSpace(string(buf[:n]))
			fmt.Printf("[HP] Recibido de %s: %s\n", addr.String(), msg)

			if msg == "SYN" {
				// Responder "SYN-ACK"
				_, err := conn.WriteToUDP([]byte("SYN-ACK"), addr)
				if err != nil {
					fmt.Printf("Error enviando SYN-ACK a %s: %v\n", addr, err)
				}
			} else if msg == "SYN-ACK" {
				// Confirmamos que el peer recibió nuestro "SYN"
				fmt.Printf("Recibido SYN-ACK de %s => NAT abierto en ambos lados.\n", addr)
				done <- true
				return
			}
		}
	}()

	// 3) Esperar a que se reciba "SYN-ACK" o que ocurra timeout
	select {
	case <-done:
		close(stop)
		return nil
	case <-time.After(overallTimeout):
		close(stop)
		return fmt.Errorf("timeout en hole punching bidireccional")
	}
}

// startWireGuard genera un archivo de configuración para WireGuard e invoca wg-quick up.
// Se utiliza el puerto local (51820) y se configura la sección [Peer] con la clave pública remota,
// el endpoint (mapeo NAT del otro peer) y AllowedIPs.
func startWireGuard(peerID, listenPort, wgPrivateKey, wgAddress, wgPeerPublicKey, peerEndpoint, allowedIPs string) error {
	configPath := fmt.Sprintf("/tmp/wg-%s.conf", peerID)
	configContent := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
ListenPort = %s

[Peer]
PublicKey = %s
Endpoint = %s
PersistentKeepalive = 25
AllowedIPs = %s
`, wgPrivateKey, wgAddress, listenPort, wgPeerPublicKey, peerEndpoint, allowedIPs)

	err := os.WriteFile(configPath, []byte(configContent), 0600)
	if err != nil {
		return fmt.Errorf("error escribiendo archivo de configuración: %v", err)
	}
	fmt.Printf("Archivo de configuración WireGuard escrito en %s:\n%s\n", configPath, configContent)

	cmd := exec.Command("wg-quick", "up", configPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error ejecutando wg-quick up: %v, output: %s", err, output)
	}
	fmt.Printf("Salida de wg-quick up:\n%s\n", output)
	return nil
}

// derivePublicKey deriva la clave pública a partir de la clave privada de WireGuard.
// La clave privada se recibe en base64 y la función devuelve la clave pública en base64.
func derivePublicKey(wgPrivateKey string) string {
	privBytes, err := base64.StdEncoding.DecodeString(wgPrivateKey)
	if err != nil {
		log.Fatalf("Error decodificando la clave privada: %v", err)
	}
	if len(privBytes) != 32 {
		log.Fatalf("La clave privada debe tener 32 bytes, tiene %d", len(privBytes))
	}
	pubBytes, err := curve25519.X25519(privBytes, curve25519.Basepoint)
	if err != nil {
		log.Fatalf("Error derivando la clave pública: %v", err)
	}
	return base64.StdEncoding.EncodeToString(pubBytes)
}
