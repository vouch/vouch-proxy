package context

// Key named keys for context map
type Key string

func (c Key) String() string {
	return "mypackage context key " + string(c)
}

var StatusCode = Key("statusCode")
