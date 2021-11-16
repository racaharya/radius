package rfc4679

import (
	"testing"

	"github.com/holgermetschulat/radius"
	"github.com/holgermetschulat/radius/rfc2865"
	"github.com/holgermetschulat/radius/rfc2866"
	"github.com/stretchr/testify/assert"
)

func TestSetVendorMalformedVSAs(t *testing.T) {
	a := assert.New(t)
	var err error

	packet := radius.New(radius.CodeAccessAccept, []byte("secret"))

	malformedTooShort := radius.Attribute([]byte{1, 1, 1})
	malformedTooShortVendor, err := radius.NewVendorSpecific(_ADSLForum_VendorID, malformedTooShort)
	a.Nil(err)
	malformedTooShortAVP := &radius.AVP{
		Type:      rfc2865.VendorSpecific_Type,
		Attribute: malformedTooShortVendor,
	}

	malformedTooLong := radius.Attribute([]byte{1, 255, 1})
	malformedTooLongVendor, err := radius.NewVendorSpecific(_ADSLForum_VendorID, malformedTooLong)
	a.Nil(err)
	malformedTooLongAVP := &radius.AVP{
		Type:      rfc2865.VendorSpecific_Type,
		Attribute: malformedTooLongVendor,
	}
	packet.Attributes = append(packet.Attributes, malformedTooShortAVP, malformedTooLongAVP)

	attr := radius.Attribute([]byte("asdf"))
	err = _ADSLForum_SetVendor(packet, 1, attr)
	a.Nil(err)
	err = _ADSLForum_SetVendor(packet, 1, attr)
	a.Nil(err)

	adslAttribsType1 := _ADSLForum_GetsVendor(packet, 1)
	a.Len(adslAttribsType1, 1)
	a.Len(packet.Attributes, 3) // malformed attributes despite of being the same type are not being overwritten
}

func TestSetVendorGroupedMalformedVSAs(t *testing.T) {
	a := assert.New(t)
	var err error

	packet := radius.New(radius.CodeAccessAccept, []byte("secret"))

	malformedGrouped := radius.Attribute([]byte{ 1, 3, 'X' , 1, 255, 1})
	malformedGroupedVendor, err := radius.NewVendorSpecific(_ADSLForum_VendorID, malformedGrouped)
	a.Nil(err)
	malformedGroupedAVP := &radius.AVP{
		Type:      rfc2865.VendorSpecific_Type,
		Attribute: malformedGroupedVendor,
	}

	packet.Attributes = append(packet.Attributes, malformedGroupedAVP)

	attr := radius.Attribute([]byte("asdf"))
	err = _ADSLForum_SetVendor(packet, 1, attr)
	a.Nil(err)
	err = _ADSLForum_SetVendor(packet, 1, attr)
	a.Nil(err)

	adslAttribsType1 := _ADSLForum_GetsVendor(packet, 1)
	a.Len(adslAttribsType1, 1) // in the grouped VSAs the valid vsa is removed, the malformed one is not removed but it is not returned here as it is invalid

	a.Len(packet.Attributes, 2)
	for _,a := range packet.Attributes {
		t.Logf("%+v",a)
	}
}

func TestSetVendorGroupedVSAs(t *testing.T) {
	a := assert.New(t)

	packet := radius.New(radius.CodeAccessAccept, []byte("secret"))

	groupedVSAs := radius.Attribute([]byte{1, 3, 1, 2, 3, 1})
	groupedVendorVSAs, err := radius.NewVendorSpecific(_ADSLForum_VendorID, groupedVSAs)
	a.Nil(err)
	malformed := &radius.AVP{
		Type:      rfc2865.VendorSpecific_Type,
		Attribute: groupedVendorVSAs,
	}
	packet.Attributes = append(packet.Attributes, malformed)

	attr := radius.Attribute([]byte("asdf"))
	err = _ADSLForum_SetVendor(packet, 1, attr)
	a.Nil(err)
	err = _ADSLForum_SetVendor(packet, 1, attr)
	a.Nil(err)

	adslAttribsType1 := _ADSLForum_GetsVendor(packet, 1)
	a.Len(adslAttribsType1, 1)
	a.Len(packet.Attributes, 2)
}

func TestSetVendor(t *testing.T) {
	a := assert.New(t)

	packet := radius.New(radius.CodeAccessAccept, []byte("secret"))

	err := rfc2866.AcctStatusType_Set(packet, rfc2866.AcctStatusType_Value_Start)
	a.Nil(err)
	err = rfc2866.AcctInputOctets_Set(packet, rfc2866.AcctInputOctets(1))
	a.Nil(err)

	attr := radius.Attribute([]byte("asdf"))
	err = _ADSLForum_SetVendor(packet, 2, attr)
	a.Nil(err)
	err = _ADSLForum_SetVendor(packet, 1, attr)
	a.Nil(err)
	err = _ADSLForum_SetVendor(packet, 1, attr)
	a.Nil(err)

	adslAttribsType1 := _ADSLForum_GetsVendor(packet, 1)
	a.Len(adslAttribsType1, 1)
	adslAttribsType2 := _ADSLForum_GetsVendor(packet, 2)
	a.Len(adslAttribsType2, 1)
	a.Len(packet.Attributes, 4)
}

func TestSetVendorNoStandardAttributes(t *testing.T) {
	a := assert.New(t)

	packet := radius.New(radius.CodeAccessAccept, []byte("secret"))

	attr := radius.Attribute([]byte("asdf"))
	err := _ADSLForum_SetVendor(packet, 1, attr)
	a.Nil(err)
	err = _ADSLForum_SetVendor(packet, 2, attr)
	a.Nil(err)
	err = _ADSLForum_SetVendor(packet, 1, attr)
	a.Nil(err)

	adslAttribsType1 := _ADSLForum_GetsVendor(packet, 1)
	a.Len(adslAttribsType1, 1)
	adslAttribsType2 := _ADSLForum_GetsVendor(packet, 2)
	a.Len(adslAttribsType2, 1)
	a.Len(packet.Attributes, 2)
}

func TestSetVendorNoVendorAttributes(t *testing.T) {
	a := assert.New(t)

	packet := radius.New(radius.CodeAccessAccept, []byte("secret"))

	attr := radius.Attribute([]byte("asdf"))
	err := _ADSLForum_SetVendor(packet, 1, attr)
	a.Nil(err)
	err = _ADSLForum_SetVendor(packet, 1, attr)
	a.Nil(err)

	adslAttribs := _ADSLForum_GetsVendor(packet, 1)
	a.Len(adslAttribs, 1)
	a.Len(packet.Attributes, 1)
}

func TestHolger(t *testing.T) {
	a := assert.New(t)

	packet := radius.New(radius.CodeAccessAccept, []byte("secret"))

	groupedVSAs := radius.Attribute([]byte{1, 3, 1,      2, 3, 'X'})
	groupedVendorVSAs, err := radius.NewVendorSpecific(_ADSLForum_VendorID, groupedVSAs)
	a.Nil(err)
	malformed := &radius.AVP{
		Type:      rfc2865.VendorSpecific_Type,
		Attribute: groupedVendorVSAs,
	}
	packet.Attributes = append(packet.Attributes, malformed)

	attr := radius.Attribute([]byte("asdf"))
	err = _ADSLForum_SetVendor(packet, 2, attr)
	a.Nil(err)
	err = _ADSLForum_SetVendor(packet, 2, attr)
	a.Nil(err)

	adslAttribsType2 := _ADSLForum_GetsVendor(packet, 2)
	a.Len(adslAttribsType2, 1) // only 1 time "asdf"
	a.Len(packet.Attributes, 2) // "asdf" is appended as a non-grouped attribute
	for _,a := range packet.Attributes {
		t.Logf("%+v",a)
	}
}

func TestHolger2(t *testing.T) {
	a := assert.New(t)

	packet := radius.New(radius.CodeAccessAccept, []byte("secret"))

	unrelatedgroupedVSAs := radius.Attribute([]byte{99, 3, 'Z'})
	unrelatedgroupedVendorVSAs, err := radius.NewVendorSpecific(_ADSLForum_VendorID, unrelatedgroupedVSAs)
	a.Nil(err)
	avpUnrelated := &radius.AVP{
		Type:      rfc2865.VendorSpecific_Type,
		Attribute: unrelatedgroupedVendorVSAs,
	}
	packet.Attributes = append(packet.Attributes, avpUnrelated)


	groupedVSAs := radius.Attribute([]byte{1, 3, 'X'})
	groupedVendorVSAs, err := radius.NewVendorSpecific(_ADSLForum_VendorID, groupedVSAs)
	a.Nil(err)
	malformed := &radius.AVP{
		Type:      rfc2865.VendorSpecific_Type,
		Attribute: groupedVendorVSAs,
	}
	packet.Attributes = append(packet.Attributes, malformed)
	// add second time, create a duplicate VSA intentionally
	packet.Attributes = append(packet.Attributes, malformed)

	attr := radius.Attribute([]byte("asdf"))
	err = _ADSLForum_SetVendor(packet, 1, attr)
	a.Nil(err)

	adslAttribsType1 := _ADSLForum_GetsVendor(packet, 1)
	a.Len(adslAttribsType1, 1) // only 1 time "asdf"
	a.Len(packet.Attributes, 2) // "asdf" is appended as a non-grouped attribute
	for _,a := range packet.Attributes {
		t.Logf("%+v",a)
	}
}
