package main

import (
	"archive/zip"
	"compress/flate"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/okteto/go-getting-started/common"
)

var errInvalidWrite = errors.New("invalid write result")
var ErrShortWrite = errors.New("short write")

type ByteSize float64

const (
	_           = iota // ignore first value by assigning to blank identifier
	KB ByteSize = 1 << (10 * iota)
	MB
	GB
	TB
	PB
	EB
	ZB
	YB
)

type DownloadStaus int

const (
	DOWNLOAD_STAUS_NOT_EXIST DownloadStaus = iota
	DOWNLOAD_STAUS_ING
	DOWNLOAD_STAUS_ED
	DOWNLOAD_STAUS_ERROR
	DOWNLOAD_STAUS_WRITE_ERROR
)

func (ds DownloadStaus) String() string {
	switch ds {
	case DOWNLOAD_STAUS_NOT_EXIST:
		return "DOWNLOAD_STAUS_NOT_EXIST"
	case DOWNLOAD_STAUS_ING:
		return "DOWNLOAD_STAUS_ING"
	case DOWNLOAD_STAUS_ED:
		return "DOWNLOAD_STAUS_ED"
	case DOWNLOAD_STAUS_ERROR:
		return "DOWNLOAD_STAUS_ERROR"
	case DOWNLOAD_STAUS_WRITE_ERROR:
		return "DOWNLOAD_STAUS_WRITE_ERROR"
	}
	return "unknown"
}

type DownloadProcess struct {
	Status DownloadStaus
	Size   string
}
type DownloadFileInfo struct {
	Name    string
	Process DownloadProcess
}
type MessageType int

const (
	MESSAGE_TYPE_UPDATE MessageType = iota
	MESSAGE_TYPE_QUERY
)

func (mt MessageType) String() string {
	switch mt {
	case MESSAGE_TYPE_UPDATE:
		return "MESSAGE_TYPE_UPDATE"
	case MESSAGE_TYPE_QUERY:
		return "MESSAGE_TYPE_QUERY"
	}
	return "unknown"
}

type MessageUnit struct {
	DownloadInfo   DownloadFileInfo
	ReceiveChannel chan string
	Type           MessageType
}

// type Messagechannel struct {
// 	Channel chan MessageUnit
// }

func (b ByteSize) String() string {
	switch {
	case b >= YB:
		return fmt.Sprintf("%.2fYB", b/YB)
	case b >= ZB:
		return fmt.Sprintf("%.2fZB", b/ZB)
	case b >= EB:
		return fmt.Sprintf("%.2fEB", b/EB)
	case b >= PB:
		return fmt.Sprintf("%.2fPB", b/PB)
	case b >= TB:
		return fmt.Sprintf("%.2fTB", b/TB)
	case b >= GB:
		return fmt.Sprintf("%.2fGB", b/GB)
	case b >= MB:
		return fmt.Sprintf("%.2fMB", b/MB)
	case b >= KB:
		return fmt.Sprintf("%.2fKB", b/KB)
	}
	return fmt.Sprintf("%.2fB", b)
}
func handler(processingChannel chan MessageUnit) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receiveChannel := make(chan string)
		processingChannel <- MessageUnit{Type: MESSAGE_TYPE_QUERY, DownloadInfo: DownloadFileInfo{Name: ""}, ReceiveChannel: receiveChannel}
		downloadstatus := <-receiveChannel
		fmt.Fprintf(w, "%v\n", downloadstatus)
	})
}

func search() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("r.URL.RawQuery %s\n", r.URL.RawQuery)
		if r.URL.RawQuery == "" {
			http.Error(w, fmt.Sprintf("%v\n", "[q] can not be empty !"), http.StatusBadRequest)
			return
		}
		resp, err := http.Get("https://www.google.com/search?" + r.URL.RawQuery)
		if err != nil {
			http.Error(w, fmt.Sprintf("%v\n", "[url] can not be empty !"), http.StatusBadRequest)
			return
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				log.Printf("Error closing file: %s\n", err)
			}
		}()

		for name, values := range resp.Header {
			w.Header()[name] = values
		}

		// status (must come after setting headers and before copying body)

		w.WriteHeader(resp.StatusCode)

		// body
		bytes, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("%v\n", "[url] can not be empty !"), http.StatusBadRequest)
			return
		}
		stringBody := string(bytes)
		stringBody = strings.ReplaceAll(stringBody, `<a href="/url?q=`, `<a href="`)
		stringBody = getAllurlUnit(stringBody)
		stringBody = strings.Replace(stringBody, `<head>`, `<head><meta name="viewport" content="width=device-width, initial-scale=1.0">`, 1)
		_, err = w.Write([]byte(stringBody))
		if err != nil {
			fmt.Fprintf(w, "%v", err)
			return
		}
	})
}
func getAllurlUnit(raw string) string {
	beg, end, endSecond := -1, -1, -1
	cut := raw
	// log.Printf("raw=%v\n", raw)
	begString := `<a href="`
	begStringLenth := len(begString)
	for {
		beg, end, endSecond = urlUnit(cut)
		// log.Printf("beg=%v, end=%v\n", beg, end)
		if beg == -1 || end == -1 {
			if endSecond != -1 {
				cut = cut[endSecond:]
				continue
			} else {
				break
			}

		}
		rawString, err := url.QueryUnescape(cut[beg+begStringLenth : end])
		if err != nil {
			log.Printf("QueryUnescape err %v \n", err)
			break
		}
		// log.Printf("%v \n", rawString)
		// log.Printf("%v\n\n\n", cut[beg+begStringLenth:endSecond])
		raw = strings.Replace(raw, cut[beg+begStringLenth:endSecond], rawString, 1)
		cut = cut[end:]
	}
	return raw
}
func urlUnit(raw string) (int, int, int) {
	begString := `<a href="https:`
	begStringLenth := len(begString)
	beg := strings.Index(raw, begString)
	if beg == -1 {
		return -1, -1, -1
	}
	// log.Printf("raw[beg+len(begString):]=%v\n\n", raw[beg+len(begString):])
	end := strings.Index(raw[beg+begStringLenth:], `&amp;sa=`)
	if end == -1 {
		return beg, -1, -1
	}
	endSecond := strings.Index(raw[beg+begStringLenth:], `"`)
	if endSecond == -1 {
		return beg, end, -1
	}
	if end > endSecond {
		return -1, -1, beg + begStringLenth + endSecond
	}
	// log.Printf("raw[beg:beg+end]=%v\n", raw[beg:beg+end])
	return beg, beg + begStringLenth + end, beg + begStringLenth + endSecond
}

func downloadFile(processingChannel chan MessageUnit) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, fmt.Sprintf("%v\n", err), http.StatusBadRequest)
			return
		}
		fileUrl := r.FormValue("fileUrl")
		log.Printf("fileUrl is %s!\n", fileUrl)
		if fileUrl == "" {
			http.Error(w, fmt.Sprintf("%v\n", "[url] can not be empty !"), http.StatusBadRequest)
			return
		}
		fileName := r.FormValue("fileName")
		if fileName == "" {
			splits := strings.Split(fileUrl, "/")
			if len(splits) > 1 {
				fileName = splits[len(splits)-1]
			} else {
				fileName = fileUrl
			}

		}
		useZipString := r.FormValue("useZip")
		useZip := false
		if useZipString != "" {
			useZip = true
		}
		statusNotExist := fmt.Sprintf("%v", DOWNLOAD_STAUS_NOT_EXIST)
		// log.Printf("fileName is [%v] \n", fileName)
		receiveChannel := make(chan string)
		processingChannel <- MessageUnit{Type: MESSAGE_TYPE_QUERY, DownloadInfo: DownloadFileInfo{Name: fileName}, ReceiveChannel: receiveChannel}
		downloadstatus := <-receiveChannel
		log.Printf("downloadstatus %v:[%v] \n", fileName, downloadstatus)
		if downloadstatus == statusNotExist {
			go saveFileGoroutine(fileUrl, fileName, processingChannel, useZip)
			fmt.Fprintf(w, "[%s] has add to Goroutine\n", fileName)
			return
		}
		fmt.Fprintf(w, "[%s] is downloading\n", fileName)

	})
}

func saveFileGoroutine(fileUrl, fileName string, processingChannel chan MessageUnit, useZip bool) {
	err := saveFile(fileUrl, fileName, processingChannel, useZip)
	if err != nil {
		log.Printf("%v\n", err)
	}
}
func saveFile(fileUrl, fileName string, processingChannel chan MessageUnit, useZip bool) error {
	resp, err := http.Get(fileUrl)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing file: %s\n", err)
		}
	}()
	// log.Printf("resp.Header=%v\n", resp.Header)
	var contentLength ByteSize
	if resp.ContentLength != -1 {
		contentLength = ByteSize(resp.ContentLength)
		log.Printf("ContentLength=%v\n", contentLength)
	}
	saveName := fileName
	if useZip {
		saveName = saveName + ".zip"
	}
	file, err := os.OpenFile(filepath.Join(getTmpFolderAbsPath(), saveName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("Error closing file: %s\n", err)
		}
	}()
	buf := make([]byte, 1024*100)
	var written float64 = 0
	// timeBeg := time.Now()
	// timeEnd := time.Now()
	// var speed float64 = 0
	// nCount := 0
	var dstWriter io.Writer = file
	if useZip {
		zipWrite := zip.NewWriter(file)
		dstWriter, err = zipWrite.Create(fileName)
		if err != nil {
			return err
		}
		zipWrite.RegisterCompressor(zip.Deflate, func(out io.Writer) (io.WriteCloser, error) {
			return flate.NewWriter(out, flate.BestCompression)
		})
		defer func() {
			if err := zipWrite.Close(); err != nil {
				log.Printf("Error closing zip file: %s\n", err)
			}
		}()
	}

	for {
		// timeBeg = time.Now()
		nr, er := resp.Body.Read(buf)
		if nr > 0 {
			nw, ew := dstWriter.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errInvalidWrite
				}
			}
			// timeBeg = timeEnd
			//
			written += float64(nw)
			if written != -1 {
				// nCount = nCount + 1
				// speed = speed + float64(nw)
				// if nCount >= 1000 {
				// 	timeEnd = time.Now()
				// 	duration := timeEnd.Sub(timeBeg).Seconds()
				// 	// log.Printf("duration:%v\n", duration)
				// 	timeBeg = timeEnd
				// 	log.Printf("download:%v/s\n", ByteSize(speed/duration))
				// 	nCount = 0
				// 	speed = 0
				// }
				processingChannel <- MessageUnit{Type: MESSAGE_TYPE_UPDATE, DownloadInfo: DownloadFileInfo{Name: fileName, Process: DownloadProcess{Status: DOWNLOAD_STAUS_ING, Size: fmt.Sprintf("%v/%v", ByteSize(written), contentLength)}}}
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}

	// _, err = io.CopyBuffer(file, resp.Body, buffer)
	if err != nil {
		return err
	}
	// timeEnd := time.Now()

	log.Printf("saved [%v]\n", fileName)
	processingChannel <- MessageUnit{Type: MESSAGE_TYPE_UPDATE, DownloadInfo: DownloadFileInfo{Name: fileName, Process: DownloadProcess{Status: DOWNLOAD_STAUS_ED, Size: fmt.Sprintf("%v/%v", ByteSize(written), contentLength)}}}
	return nil
}
func getTmpFolderAbsPath() string {
	return filepath.Join(common.CurrentPath(), "tmpfiles")
}

// Start
func Start(port string) {
	log.Printf("start %v\n", getTmpFolderAbsPath())
	log.Printf("port %v\n", port)
	// addr := flag.String("addr", `:`+port, "HTTP network address")
	err := os.MkdirAll(getTmpFolderAbsPath(), os.ModePerm)
	if err != nil {
		log.Printf("%v\n", err)
		return
	}
	useHttps := true
	certFilePath := filepath.Join(common.CurrentPath(), `certs`, `certFile`)
	keyFilePath := filepath.Join(common.CurrentPath(), `certs`, `keyFile`)
	if common.IsFileNotExist(certFilePath) || common.IsFileNotExist(keyFilePath) {
		useHttps = false
	}
	log.Printf("useHttps %v\n", useHttps)
	processingChannel := make(chan MessageUnit, 50)
	go updateProcess(processingChannel)

	mux := http.NewServeMux()

	mux.Handle("/tmpfiles/", bannedIPHandler(http.StripPrefix("/tmpfiles/", http.FileServer(http.Dir(getTmpFolderAbsPath())))))
	mux.Handle("/downloadUrl", bannedIPHandler(downloadFile(processingChannel)))
	mux.Handle("/search", bannedIPHandler(search()))
	// http.HandleFunc("/url", url)
	mux.Handle("/", bannedIPHandler(handler(processingChannel)))
	readTimeout := 60 * time.Second
	writeTimeout := 60 * time.Second
	if !useHttps {
		srv := &http.Server{
			Addr:         `:` + port,
			Handler:      mux,
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
			// TLSConfig: &tls.Config{
			// 	MinVersion:               tls.VersionTLS13,
			// 	PreferServerCipherSuites: true,
			// 	ClientCAs:                clientCertPool,
			// 	ClientAuth:               tls.RequireAndVerifyClientCert,
			// },
		}
		log.Fatal(srv.ListenAndServe())
		return
	}

}
func updateProcess(processingChannel chan MessageUnit) {
	statusList := make(map[string]DownloadProcess)
	for {
		// log.Printf("receive: [%+v]\n", <-processingChannel)
		message := <-processingChannel
		// log.Printf("message: [%+v]\n", message)
		if message.Type == MESSAGE_TYPE_UPDATE {
			if message.DownloadInfo.Process.Status == DOWNLOAD_STAUS_ING {
				statusList[message.DownloadInfo.Name] = message.DownloadInfo.Process
			} else {
				delete(statusList, message.DownloadInfo.Name)
			}

		} else if message.Type == MESSAGE_TYPE_QUERY {
			if message.ReceiveChannel == nil {
				log.Printf("%v\n", `can not send message because ReceiveChannel is nil`)
				continue
			}
			if message.DownloadInfo.Name == "" {

				message.ReceiveChannel <- fmt.Sprintf("%v", statusList)
				continue
			}
			if _, ok := statusList[message.DownloadInfo.Name]; ok {
				message.ReceiveChannel <- fmt.Sprintf("%v", statusList[message.DownloadInfo.Name].Status)
			} else {
				message.ReceiveChannel <- fmt.Sprintf("%v", DOWNLOAD_STAUS_NOT_EXIST)
				statusList[message.DownloadInfo.Name] = DownloadProcess{Status: DOWNLOAD_STAUS_ING}
			}
		}
		// if statusList[p] {

		// }
	}
}
func bannedIPHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if common.IsBannedIP(common.ReadHttpIP(r)) {
			http.Error(w, "Can't find your request page !\n", http.StatusNotFound)
			return
		}
		h.ServeHTTP(w, r)
	})
}
func redirectTLS() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		url := "https://" + r.Host + r.URL.String()
		http.Redirect(w, r, url, http.StatusMovedPermanently)
	})
}
