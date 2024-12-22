package main

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	ctX509 "github.com/google/certificate-transparency-go/x509"
	ctx509util "github.com/google/certificate-transparency-go/x509util"
)

/////////////////////////////// Global variables with all data about certificates

type LogAndLogEntry struct {
	logURL   string
	logEntry *ct.LogEntry
}

var Certs = make(map[string]*ctX509.Certificate)
var CertsToLogEntries = make(map[string][]LogAndLogEntry)

/////////////////////////////// Constant log IDs, URLs and keys

var LogIDToUrl = map[string]string{
	"3q1pSgrz1CuGgkHUXu8FY/vPalFD4txiGoRf6J9Qm90=": "https://ct-agate.yandex.net/2023/",
	"lbNyiSAplLRaDFkkJKRZIP0UsSRnxHSLZzoD4BJVM9c=": "https://ct-agate.yandex.net/2024/",
	"AK5JUqPU3NHFnCCdj1yMRrYyI2hpT8AhGrUT+YUvLD4=": "https://ct-agate.yandex.net/2025/",
	"Vh7HRN8a9wLmJoOt38SVz3WjGwxs6KDH6gEDMJC3SIU=": "https://ct-agate.yandex.net/2026/",
	"6ZZ4aoGLsN0Eju61DrPM1QW9JU7I9VhOrVAlCgoEyNU=": "https://ctlog2023.mail.ru/nca2023/",
	"rDw/UOE3a7Y0dFbd8Tuykdn+zHtt8vEjum/yqNS5okI=": "https://ctlog2024.mail.ru/nca2024/",
	"bCNAWMiH5pnuZFXTlW/j/62SNDlIhVdGoZ1FcjNaa+k=": "https://ctlog2025.mail.ru/nca2025/",
	"eNkSvkIKwAIcul2iVDKRU9tIywYr/EMBJB4Qq8cWnmc=": "https://ctlog2026.mail.ru/nca2026/",
	"NDMxNjYzMDU1NTczNDI2MzE1Mg==":                 "https://23.ctlog.digital.gov.ru/2023/",
	"TrrllSeS1+gnq4xwLwGc3WNPWSn8R0gYjdEvXpsBAmM=": "https://24.ctlog.digital.gov.ru/2024/",
	"geCHp9endLWg6BvNE84di766qzqf01beMSQqeKy44Dc=": "https://25.ctlog.digital.gov.ru/2025/",
	"ybgRvMAcYl3KJ/TWxEfLX34Ov3LLWZGoMy+Zv5oqPko=": "https://26.ctlog.digital.gov.ru/2026/",
}
var LogURLToPublicKey = map[string]string{
	"https://ct-agate.yandex.net/2023/":  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhxjLY9zBQZk5VmyjKd/Ej6KfBLNE2OKnd+LdyXIsa1kPkXqyVlLWEfQE7bYSZOt2UXYscRsVFOyqxwGYU0yjBw==",
	"https://ct-agate.yandex.net/2024/":  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZf3JmDiqxpMZO3Rw3ngtmd2uSlGdMpLtNEVjmXKrXSEtIl4L7n3gCHq/+upBALiMalQP1E47Epx0qFGXELA5lQ==",
	"https://ct-agate.yandex.net/2025/":  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/6VEmCoHZsAs/TEny2jmYieIyzzo6ezT1J6YITXziFPh4ySWVCHHN1MLzxpOvcdZYoTwGTS8zjjuJB2P9esj3g==",
	"https://ct-agate.yandex.net/2026/":  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAQAIwfEbBkUu1RDSLnlcGoVlMbRc8wQC1yusWLBDR8c3cJIyk0HtI+Uwfga99z4/7Mt8fkSwVTGQkMkiv4UsTw==",
	"https://ctlog2023.mail.ru/nca2023/": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUidX4EB6GdgGoQC0u1VOokaLh7cfN66CTZ/zLc9brtppE9LNNyRZ9MXl+YTqQ/YxNi/CkXfbV9xMC4tVKN//ng==",
	"https://ctlog2024.mail.ru/nca2024/": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExq6Wp2YmLNAhaM5DkoPr0K6Xa7mX9cq0rm87NGX26BtpUMimgwuWBLFm0ImD2dgO7JdZJJg6T9qG9EqOWg1o2g==",
	"https://ctlog2025.mail.ru/nca2025/": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9QNHyel7QqVc/uyN3kYIjg4jGTAsCNEGij5n/09wrwlr7J6VP1p+GsH/PDwMPG3xsQaRwnF9rBqKksvIfE/gHg==",
	"https://ctlog2026.mail.ru/nca2026/": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErRmHL0jQ8p4csgKnL1NdFLWeLVQ24UkE6XuMwfzV0kYxklCMo6xKBOY4TZXPRtrqY1NVNIR4Sl6VoGSs2lfpaw==",
	//"https://23.ctlog.digital.gov.ru/2023/": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMrvKMpGZgzS8GWcmVZmTCTc353lZmlF2bT6RxCNvtaVX0Pk5zKqJaS8YUuV+9XhVAJ1EiXh1LoHnyGJTi3GslQ==",
	"https://24.ctlog.digital.gov.ru/2024/": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESsbeAkQGAsByPKpOK4RI7pV39N/Z9DtJ4VCG06iyLgWipPDUnjKQPhiF/l6juQS0k1lFNCGTJuH0GjqM806fLQ==",
	"https://25.ctlog.digital.gov.ru/2025/": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETWXlfpI1faK8Kl1WxVMKRgJj/zL/Fdr5QJ/khIrxHVFKViDZkqdBlxZ2SLSOSHbzHITeRvBvBnh+qZ5rHIsZ3Q==",
	"https://26.ctlog.digital.gov.ru/2026/": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELLlQEbDY7eHMYWce3m5g4IhuYGK0k8mCNw7G4rRJuJAgATGv2ODHJsRnKAkyj2kvXRp9LqRGAJDVqyPtdXs8bA==",
}

/////////////////////////////// Collecting certs from logs using RFC 6962 API

func getLenOfLog(url string) int64 {
	var sth ct.SignedTreeHead
	urlAPI := fmt.Sprintf(url + "ct/v1/get-sth")
	resp, err := http.Get(urlAPI)
	if err != nil {
		log.Println("ERROR http.Get", urlAPI, err)
	}
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		log.Println("ERROR buf.ReadFrom", urlAPI, err)
	}
	err = json.Unmarshal(buf.Bytes(), &sth)
	if err != nil {
		log.Println("ERROR json.Unmarshal", urlAPI, err)
	}
	return int64(sth.TreeSize)
}
func getCerts(start int64, end int64, url string) ct.GetEntriesResponse {
	urlAPI := fmt.Sprintf(url+"ct/v1/get-entries?start=%d&end=%d", start, end)
	resp, err := http.Get(urlAPI)
	if err != nil {
		log.Println("ERROR http.Get", urlAPI, err)
	}
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		log.Println("ERROR buf.ReadFrom", urlAPI, err)
	}
	var results ct.GetEntriesResponse
	err = json.Unmarshal(buf.Bytes(), &results)
	if err != nil {
		log.Println("ERROR json.Unmarshal", urlAPI, err)
	}
	return results
}
func getAndParseCerts(startIndex int64, endIndex int64, url string) {
	var i int64
	for i = startIndex; i < endIndex; i += 50 {
		certs := getCerts(i, i+49, url)
		for j, leafEntry := range certs.Entries {
			parsedEntry, e := ct.LogEntryFromLeaf(i+int64(j), &leafEntry)
			if e != nil {
				log.Printf("ERROR (LogEntryFromLeaf(log = %s, certNum = %d)) : %s\n", url, i+int64(j), e.Error())
				return
			}

			var cert *ctX509.Certificate
			var err error
			if parsedEntry.X509Cert != nil {
				cert = parsedEntry.X509Cert
			} else if parsedEntry.Precert != nil {
				cert, err = ctX509.ParseCertificate(parsedEntry.Precert.Submitted.Data)
				if err != nil {
					log.Println("Error parsing precert, certNum =", i+int64(j), err)
				}
			} else {
				log.Println("Not a cert and not precert, certNum =", i+int64(j), err)
				cert = nil
			}

			if cert != nil {
				hashString := certHash(cert)
				Certs[hashString] = cert
				CertsToLogEntries[hashString] = append(CertsToLogEntries[hashString], LogAndLogEntry{url, parsedEntry})
			}
		}
	}
}
func collectLogs() {
	for logURL := range LogURLToPublicKey {
		size := getLenOfLog(logURL)
		getAndParseCerts(0, size, logURL)
	}
}

/////////////////////////////// Service functions

func certHash(cert *ctX509.Certificate) string {
	hash := sha256.New()
	hash.Write(cert.Raw)
	return string(hash.Sum(nil))
}
func csvWriter(header []string, data [][]string, name string) {
	file, err := os.Create(name + ".csv")
	if err != nil {
		log.Println("ERROR creating csv:", err)
		return
	}
	writer := csv.NewWriter(file)
	if err := writer.Write(header); err != nil {
		log.Println("ERROR writing to csv:", err)
		return
	}
	for _, record := range data {
		if err := writer.Write(record); err != nil {
			log.Println("ERROR writing to csv:", err)
			return
		}
	}
	writer.Flush()
	err = file.Close()
	if err != nil {
		log.Println("ERROR closing csv file:", err)
	}
	log.Println("Created CSV file " + name)
}

/////////////////////////////// Primary functions

func analyseLogs() {
	var CA = make(map[string]int)
	var CAUsage = make(map[string]int)
	var CAErrorDial = make(map[string]int)
	var LogSCTCount = make(map[string]int)
	var usedData = make([][]string, 0, 1000)
	var usedDataHeader = []string{"SerialNumber", "CommonName", "NotBefore", "Issuer", "SAN", "RawBase64"}
	var errorData = make([][]string, 0, 1000)
	var errorDataHeader = []string{"SerialNumber", "CommonName", "NotBefore", "Issuer", "Error", "SCTTimestamp", "LogTimestamp", "LogURL", "LogIndex", "LogEntries", "RawBase64"}
	var certData = make([][]string, 0, 1000)
	var certDataHeader = []string{"SerialNumber", "CommonName", "NotBefore", "Issuer", "CanDial", "Used", "SCTError", "SAN", "LogEntries", "RawBase64"}

	var wg, wgReaders sync.WaitGroup
	wg.Add(len(Certs))
	wgReaders.Add(5)
	var usageChannel = make(chan *ctX509.Certificate, 100)
	var logSCTChannel = make(chan string, 100)
	var errorDialChannel = make(chan *ctX509.Certificate, 100)
	var errorDataChannel = make(chan []string, 100)
	var certChannel = make(chan []string, 100)

	go func() {
		for cert := range usageChannel {
			CAUsage[cert.Issuer.CommonName]++
			usedData = append(usedData, []string{fmt.Sprintf("0%X ", cert.SerialNumber), cert.Subject.CommonName, cert.NotBefore.Format(time.DateTime), cert.Issuer.CommonName, fmt.Sprint(cert.DNSNames), base64.StdEncoding.EncodeToString(cert.Raw)})
		}
		wgReaders.Done()
	}()
	go func() {
		for logURL := range logSCTChannel {
			LogSCTCount[logURL]++
		}
		wgReaders.Done()
	}()
	go func() {
		for cert := range errorDialChannel {
			CAErrorDial[cert.Issuer.CommonName]++
		}
		wgReaders.Done()
	}()
	go func() {
		for errData := range errorDataChannel {
			errorData = append(errorData, errData)
		}
		wgReaders.Done()
	}()
	go func() {
		for oneCertData := range certChannel {
			certData = append(certData, oneCertData)
		}
		wgReaders.Done()
	}()

	for _, cert := range Certs {
		CA[cert.Issuer.CommonName]++
		go processCert(cert, &wg, usageChannel, errorDialChannel, logSCTChannel, errorDataChannel, certChannel)
	}

	wg.Wait()
	close(usageChannel)
	close(errorDialChannel)
	close(logSCTChannel)
	close(errorDataChannel)
	close(certChannel)
	wgReaders.Wait()

	for issuer, amount := range CA {
		log.Printf("ALL: %5d USED: %4d (%2d%%) ERROR DIALING: %4d (%2d%%) from %s\n", amount, CAUsage[issuer], CAUsage[issuer]*100/amount, CAErrorDial[issuer], CAErrorDial[issuer]*100/amount, issuer)
	}
	for url, amount := range LogSCTCount {
		log.Printf("SCT amount: %4d from %s\n", amount, url)
	}

	sortByNotBeforeTimeFunc := func(a []string, b []string) int {
		return cmp.Compare(a[2], b[2])
	}
	slices.SortFunc(usedData, sortByNotBeforeTimeFunc)
	slices.SortFunc(errorData, sortByNotBeforeTimeFunc)
	slices.SortFunc(certData, sortByNotBeforeTimeFunc)

	csvWriter(usedDataHeader, usedData, "UsedCertificates")
	csvWriter(errorDataHeader, errorData, "SCTErrors")
	csvWriter(certDataHeader, certData, "AllCertificates")
	log.Println("Detailed info about errors with SCT see in file SCTErrors.csv, AllCertificates.csv contains only fact about SCT error occured.")
}
func processCert(cert *ctX509.Certificate, wg *sync.WaitGroup, usageChannel, errorDialChannel chan *ctX509.Certificate, logSCTChannel chan string, errorDataChannel, certChannel chan []string) {
	defer wg.Done()
	var logger = log.New(os.Stdout, fmt.Sprintf("SN: %34s", fmt.Sprintf("0%X ", cert.SerialNumber)), log.LstdFlags)
	var foundCert *ctX509.Certificate
	var names = append(cert.DNSNames, cert.Subject.CommonName)
	var foundUsage, foundHost, SCTError bool
	var hashString = certHash(cert)
	var logEntries = make([]string, len(CertsToLogEntries[hashString]))
	for i := range CertsToLogEntries[hashString] {
		logEntries[i] = CertsToLogEntries[hashString][i].logURL
	}

	for _, name := range names {
		if foundUsage {
			break
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", name+":443", &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			continue
		}
		foundHost = true
		foundCert, err = ctX509.ParseCertificate(conn.ConnectionState().PeerCertificates[0].Raw)
		if err != nil {
			logger.Println("ERROR ctX509.ParseCertificate:", err)
			continue
		}
		if foundCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			foundUsage = true
			for i := range foundCert.SCTList.SCTList {
				var Error, SCTTimestamp, LogTimestamp, LogURL string
				SCT, err := ctx509util.ExtractSCT(&foundCert.SCTList.SCTList[i])
				if err != nil {
					logger.Println("ERROR x509util.ExtractSCT:", err)
					continue
				}
				SCTTimestamp = time.UnixMilli(int64(SCT.Timestamp)).Format(time.DateTime)

				var entry ct.LogEntry
				var timestamp uint64
				LogURL = LogIDToUrl[ct.SHA256Hash(SCT.LogID.KeyID).Base64String()]
				if LogURL == "" {
					LogURL = "~LOG URL NOT FOUND~"
				}
				logSCTChannel <- LogURL

				for _, urlAndTimeStamp := range CertsToLogEntries[hashString] {
					if urlAndTimeStamp.logURL == LogURL {
						entry = *urlAndTimeStamp.logEntry
						timestamp = entry.Leaf.TimestampedEntry.Timestamp
						LogTimestamp = time.UnixMilli(int64(timestamp)).Format(time.DateTime)
						break
					}
				}
				if timestamp == 0 {
					SCTError = true
					Error = "SCT owner not found"
					logger.Println("ERROR", Error, name, LogURL, logEntries)
					errorDataChannel <- []string{fmt.Sprintf("0%X", cert.SerialNumber), cert.Subject.CommonName, cert.NotBefore.Format(time.DateTime), cert.Issuer.CommonName, Error, SCTTimestamp, LogTimestamp, LogURL, "0", fmt.Sprint(logEntries), base64.StdEncoding.EncodeToString(cert.Raw)}
					continue
				} else if timestamp != SCT.Timestamp {
					SCTError = true
					Error = "Timestamp is wrong"
					logger.Println("ERROR", Error, name, LogURL, SCT)
					errorDataChannel <- []string{fmt.Sprintf("0%X", cert.SerialNumber), cert.Subject.CommonName, cert.NotBefore.Format(time.DateTime), cert.Issuer.CommonName, Error, SCTTimestamp, LogTimestamp, LogURL, fmt.Sprint(entry.Index), fmt.Sprint(logEntries), base64.StdEncoding.EncodeToString(cert.Raw)}
				}

				bytesKey, err := base64.StdEncoding.DecodeString(LogURLToPublicKey[LogURL])
				if err != nil {
					logger.Println("ERROR base64.StdEncoding.DecodeString:", err)
					continue
				}
				key, err := ctX509.ParsePKIXPublicKey(bytesKey)
				if err != nil {
					logger.Println("ERROR ctX509.ParsePKIXPublicKey:", err)
					continue
				}
				vf, err := ct.NewSignatureVerifier(key)
				if err != nil {
					logger.Println("ERROR ct.NewSignatureVerifier:", err)
					continue
				}
				err = vf.VerifySCTSignature(*SCT, entry)
				if err != nil {
					SCTError = true
					Error = fmt.Sprint("SCT is not verifying: ", err)
					logger.Println("ERROR", Error, name, LogURL, SCT)
					errorDataChannel <- []string{fmt.Sprintf("0%X", cert.SerialNumber), cert.Subject.CommonName, cert.NotBefore.Format(time.DateTime), cert.Issuer.CommonName, Error, SCTTimestamp, LogTimestamp, LogURL, fmt.Sprint(entry.Index), fmt.Sprint(logEntries), base64.StdEncoding.EncodeToString(cert.Raw)}
				}
			}
		}
		err = conn.Close()
		if err != nil {
			logger.Println("ERROR conn.Close:", err)
		}
	}

	// Writing data in file Certificates
	certChannel <- []string{fmt.Sprintf("0%X", cert.SerialNumber), cert.Subject.CommonName, cert.NotBefore.Format(time.DateTime), cert.Issuer.CommonName, fmt.Sprint(foundHost), fmt.Sprint(foundUsage), fmt.Sprint(SCTError), fmt.Sprint(cert.DNSNames), fmt.Sprint(logEntries), base64.StdEncoding.EncodeToString(cert.Raw)}

	if !foundHost {
		errorDialChannel <- cert
	}
	if foundUsage {
		usageChannel <- cert
	}
}

func main() {
	collectLogs()
	analyseLogs()
}
