package main

import (
	"errors"
	"fmt"
	g "github.com/gosnmp/gosnmp"
	"math/big"
	"net"
	"strconv"
)

func WalkifHCOctets(Addr string) (IN *big.Int, OUT *big.Int, err error) {
	index, err := getInterfaceIndexByIP(Addr)
	if err != nil {
		fmt.Errorf(err.Error())
	}
	g.Default.Target = Addr
	err = g.Default.Connect()
	if err != nil {
		fmt.Errorf("Connect() err: %v", err)
	}
	defer g.Default.Conn.Close()
	oids := []string{"1.3.6.1.2.1.31.1.1.1.6." + strconv.Itoa(index), "1.3.6.1.2.1.31.1.1.1.10." + strconv.Itoa(index)}
	result, err2 := g.Default.Get(oids)
	if err2 != nil {
		fmt.Errorf("Get() err: %v", err2)
		return nil, nil, err2
	}
	return g.ToBigInt(result.Variables[0].Value), g.ToBigInt(result.Variables[1].Value), nil
}
func getInterfaceIndexByIP(addr string) (int, error) {
	ip := net.ParseIP(addr)
	interfaces, err := net.Interfaces()
	if err != nil {
		return 0, err
	}
	for _, iface := range interfaces {
		if addrs, err := iface.Addrs(); err == nil {
			for _, addr := range addrs {
				if iip, _, err := net.ParseCIDR(addr.String()); err == nil {
					if iip.Equal(ip) {
						return iface.Index, nil
					}
				} else {
					continue
				}
			}
		} else {
			continue
		}
	}
	return 0, errors.New("couldn't find a interface for the ip")
}
