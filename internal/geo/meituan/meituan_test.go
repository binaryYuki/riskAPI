package meituan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func fakeAPI(t *testing.T, ipBody, locBody string, gotTag *string) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ip" {
			_, _ = w.Write([]byte(ipBody))
			return
		}
		*gotTag = r.URL.Query().Get("tag")
		_, _ = w.Write([]byte(locBody))
	}))
	t.Cleanup(srv.Close)
	oldIP, oldLoc := ipAPI, locationAPI
	ipAPI, locationAPI = srv.URL+"/ip", srv.URL+"/latlng"
	t.Cleanup(func() { ipAPI, locationAPI = oldIP, oldLoc })
}

func TestQueryNotFound(t *testing.T) {
	var tag string
	fakeAPI(t, `{"error":{"code":404,"type":"Data Not found","message":"Can Not Loc"}}`, `{}`, &tag)
	_, err := Query(context.Background(), "211.97.6.117", nil, QueryOptions{})
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestReverseGeocode(t *testing.T) {
	var tag string
	fakeAPI(t, `{}`, `{"data":{"country":"中国","province":"河南省","city":"郑州","district":"金水区","areaName":"郑东新区CBD","isForeign":false,"lat":34.772201,"lng":113.728185}}`, &tag)
	g, err := ReverseGeocode(context.Background(), nil, 34.7732, 113.722)
	assert.NoError(t, err)
	assert.Equal(t, "1", tag)
	assert.Equal(t, "郑州", g["city"])
	assert.Equal(t, "郑东新区CBD", g["area_name"])
	assert.Equal(t, 34.772201, g["latitude"])
}

func TestReverseGeocodeEmpty(t *testing.T) {
	var tag string
	fakeAPI(t, `{}`, `{"data":{}}`, &tag)
	g, err := ReverseGeocode(context.Background(), nil, 1, 2)
	assert.NoError(t, err)
	assert.Nil(t, g)
}
