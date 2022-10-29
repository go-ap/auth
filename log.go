package auth

import (
	log "git.sr.ht/~mariusor/lw"
)

type LoggerFn func(log.Ctx, string, ...interface{})

type logger struct {
	logFn LoggerFn
	errFn LoggerFn
}

type optionFn func(*logger) error

func LogFn(logFn LoggerFn) optionFn {
	return func(l *logger) error {
		l.logFn = logFn
		return nil
	}
}

func ErrFn(logFn LoggerFn) optionFn {
	return func(l *logger) error {
		l.errFn = logFn
		return nil
	}
}

func NewLogger(opt ...optionFn) (*logger, error) {
	l := new(logger)
	l.errFn = EmptyLogFn
	l.logFn = EmptyLogFn

	for _, fn := range opt {
		if err := fn(l); err != nil {
			return nil, err
		}
	}
	return l, nil
}

var EmptyLogFn = func(log.Ctx, string, ...interface{}) {}

func (l logger) Printf(format string, v ...interface{}) {
	l.logFn(nil, format, v...)
}
func (l logger) Errorf(format string, v ...interface{}) {
	l.errFn(nil, format, v...)
}
func (l logger) Warningf(format string, v ...interface{}) {
	l.logFn(nil, format, v...)
}
func (l logger) Infof(format string, v ...interface{}) {
	l.logFn(nil, format, v...)
}
func (l logger) Debugf(format string, v ...interface{}) {
	l.logFn(nil, format, v...)
}
