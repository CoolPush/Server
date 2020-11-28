package tools

import (
	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"github.com/rifflock/lfshook"
	"github.com/sirupsen/logrus"
	easy "github.com/t-tomalak/logrus-easy-formatter"
	"time"
)

var Log *logrus.Logger

func NewLog() *logrus.Logger {
	if Log != nil {
		return Log
	}

	filePath := "warn.log"
	writer, err := rotatelogs.New(
		filePath+".%Y%m%d",
		//rotatelogs.WithLinkName(filePath),
		rotatelogs.WithRotationCount(7),
		rotatelogs.WithRotationTime(time.Duration(86400)*time.Second),
	)

	if err != nil {
		panic(err)
	}

	Log = logrus.New()

	Log.Hooks.Add(lfshook.NewHook(
		lfshook.WriterMap{
			logrus.WarnLevel:  writer,
			logrus.ErrorLevel: writer,
			logrus.FatalLevel: writer,
			logrus.PanicLevel: writer,
		},
		&easy.Formatter{
			TimestampFormat: "2006-01-02 15:04:05",
			LogFormat:       "[%time%] [%lvl%]: %msg% \n",
		},
	))
	return Log
}
