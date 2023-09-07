// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"go.mau.fi/util/random"
	mathRand "math/rand"
	"strings"

	waProto "github.com/shouyinsun/whatsmeow/binary/proto"
	"github.com/shouyinsun/whatsmeow/store"
	"github.com/shouyinsun/whatsmeow/types"
	"github.com/shouyinsun/whatsmeow/util/keys"
	waLog "github.com/shouyinsun/whatsmeow/util/log"
)

// Container is a wrapper for a SQL database that can contain multiple whatsmeow sessions.
type Container struct {
	db      *sql.DB
	dialect string
	log     waLog.Logger

	DatabaseErrorHandler func(device *store.Device, action string, attemptIndex int, err error) (retry bool)
}

var _ store.DeviceContainer = (*Container)(nil)

// New connects to the given SQL database and wraps it in a Container.
//
// Only SQLite and Postgres are currently fully supported.
//
// The logger can be nil and will default to a no-op logger.
//
// When using SQLite, it's strongly recommended to enable foreign keys by adding `?_foreign_keys=true`:
//
//	container, err := sqlstore.New("sqlite3", "file:yoursqlitefile.db?_foreign_keys=on", nil)
func New(dialect, address string, log waLog.Logger) (*Container, error) {
	db, err := sql.Open(dialect, address)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	container := NewWithDB(db, dialect, log)
	err = container.Upgrade()
	if err != nil {
		return nil, fmt.Errorf("failed to upgrade database: %w", err)
	}
	return container, nil
}

// NewWithDB wraps an existing SQL connection in a Container.
//
// Only SQLite and Postgres are currently fully supported.
//
// The logger can be nil and will default to a no-op logger.
//
// When using SQLite, it's strongly recommended to enable foreign keys by adding `?_foreign_keys=true`:
//
//	db, err := sql.Open("sqlite3", "file:yoursqlitefile.db?_foreign_keys=on")
//	if err != nil {
//	    panic(err)
//	}
//	container := sqlstore.NewWithDB(db, "sqlite3", nil)
//
// This method does not call Upgrade automatically like New does, so you must call it yourself:
//
//	container := sqlstore.NewWithDB(...)
//	err := container.Upgrade()
func NewWithDB(db *sql.DB, dialect string, log waLog.Logger) *Container {
	if log == nil {
		log = waLog.Noop
	}
	return &Container{
		db:      db,
		dialect: dialect,
		log:     log,
	}
}

const getAllDevicesQuery = `
SELECT jid, registration_id, noise_key, identity_key,
       signed_pre_key, signed_pre_key_id, signed_pre_key_sig,
       adv_key, adv_details, adv_account_sig, adv_account_sig_key, adv_device_sig,
       platform, business_name, push_name, subject_id, enable, created_time

FROM whatsmeow_device
`

const getDeviceQuery = getAllDevicesQuery + " WHERE jid=?"

const getDeviceByJidUserQuery = getAllDevicesQuery + " WHERE jid_user=? order by created_time desc limit 1 "

func (c *Container) GenerateDevice() (*store.Device, error) {
	return c.NewDevice(), nil
}

type scannable interface {
	Scan(dest ...interface{}) error
}

func (c *Container) scanDevice(row scannable) (*store.Device, error) {
	var device store.Device
	device.DatabaseErrorHandler = c.DatabaseErrorHandler
	device.Log = c.log
	device.SignedPreKey = &keys.PreKey{}
	var noisePriv, identityPriv, preKeyPriv, preKeySig []byte
	var account waProto.ADVSignedDeviceIdentity

	err := row.Scan(
		&device.ID, &device.RegistrationID, &noisePriv, &identityPriv,
		&preKeyPriv, &device.SignedPreKey.KeyID, &preKeySig,
		&device.AdvSecretKey, &account.Details, &account.AccountSignature, &account.AccountSignatureKey, &account.DeviceSignature,
		&device.Platform, &device.BusinessName, &device.PushName, &device.SubjectId, &device.Enable, &device.CreatedTime)
	if err != nil {
		return nil, fmt.Errorf("failed to scan session: %w", err)
	} else if len(noisePriv) != 32 || len(identityPriv) != 32 || len(preKeyPriv) != 32 || len(preKeySig) != 64 {
		return nil, ErrInvalidLength
	}

	device.NoiseKey = keys.NewKeyPairFromPrivateKey(*(*[32]byte)(noisePriv))
	device.IdentityKey = keys.NewKeyPairFromPrivateKey(*(*[32]byte)(identityPriv))
	device.SignedPreKey.KeyPair = *keys.NewKeyPairFromPrivateKey(*(*[32]byte)(preKeyPriv))
	device.SignedPreKey.Signature = (*[64]byte)(preKeySig)
	device.Account = &account

	innerStore := NewSQLStore(c, *device.ID)
	device.Identities = innerStore
	device.Sessions = innerStore
	device.PreKeys = innerStore
	device.SenderKeys = innerStore
	device.AppStateKeys = innerStore
	device.AppState = innerStore
	device.Contacts = innerStore
	device.ChatSettings = innerStore
	device.MsgSecrets = innerStore
	device.PrivacyTokens = innerStore
	device.Container = c
	device.Initialized = true

	return &device, nil
}

// GetAllDevices finds all the devices in the database.
func (c *Container) GetAllDevices() ([]*store.Device, error) {
	res, err := c.db.Query(getAllDevicesQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to query sessions: %w", err)
	}
	sessions := make([]*store.Device, 0)
	for res.Next() {
		sess, scanErr := c.scanDevice(res)
		if scanErr != nil {
			return sessions, scanErr
		}
		sessions = append(sessions, sess)
	}
	return sessions, nil
}

// GetFirstDevice is a convenience method for getting the first device in the store. If there are
// no devices, then a new device will be created. You should only use this if you don't want to
// have multiple sessions simultaneously.
func (c *Container) GetFirstDevice() (*store.Device, error) {
	devices, err := c.GetAllDevices()
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return c.NewDevice(), nil
	} else {
		return devices[0], nil
	}
}

// GetDevice finds the device with the specified JID in the database.
//
// If the device is not found, nil is returned instead.
//
// Note that the parameter usually must be an AD-JID.
func (c *Container) GetDevice(jid types.JID) (*store.Device, error) {
	sess, err := c.scanDevice(c.db.QueryRow(getDeviceQuery, jid))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return sess, err
}

const (
	insertDeviceQuery = `
		INSERT INTO whatsmeow_device (jid, jid_user, registration_id, noise_key, identity_key,
									  signed_pre_key, signed_pre_key_id, signed_pre_key_sig,
									  adv_key, adv_details, adv_account_sig, adv_account_sig_key, adv_device_sig,
									  platform, business_name, push_name, subject_id, enable)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE jid=?, platform=?, business_name=?, push_name=?
	`
	deleteDeviceQuery = `DELETE FROM whatsmeow_device WHERE jid=?`

	disableDeviceQuery = `update whatsmeow_device set enable = 0 where
      jid_user=? and subject_id=?`
)

// NewDevice creates a new device in this database.
//
// No data is actually stored before Save is called. However, the pairing process will automatically
// call Save after a successful pairing, so you most likely don't need to call it yourself.
func (c *Container) NewDevice() *store.Device {
	device := &store.Device{
		Log:       c.log,
		Container: c,

		DatabaseErrorHandler: c.DatabaseErrorHandler,

		NoiseKey:       keys.NewKeyPair(),
		IdentityKey:    keys.NewKeyPair(),
		RegistrationID: mathRand.Uint32(),
		AdvSecretKey:   random.Bytes(32),
	}
	device.SignedPreKey = device.IdentityKey.CreateSignedPreKey(1)
	return device
}

// ErrDeviceIDMustBeSet is the error returned by PutDevice if you try to save a device before knowing its JID.
var ErrDeviceIDMustBeSet = errors.New("device JID must be known before accessing database")

// PutDevice stores the given device in this database. This should be called through Device.Save()
// (which usually doesn't need to be called manually, as the library does that automatically when relevant).
func (c *Container) PutDevice(device *store.Device) error {
	if device.ID == nil {
		return ErrDeviceIDMustBeSet
	}
	_, err := c.db.Exec(insertDeviceQuery,
		device.ID.String(), device.ID.User, device.RegistrationID, device.NoiseKey.Priv[:], device.IdentityKey.Priv[:],
		device.SignedPreKey.Priv[:], device.SignedPreKey.KeyID, device.SignedPreKey.Signature[:],
		device.AdvSecretKey, device.Account.Details, device.Account.AccountSignature, device.Account.AccountSignatureKey, device.Account.DeviceSignature,
		device.Platform, device.BusinessName, device.PushName, device.SubjectId, 1,
		device.ID.String(), device.Platform, device.BusinessName, device.PushName)

	//save qrcode scan result
	noiseKeyPub, identityKeyPub, advKey := baseEncodeKeys(device)
	_, err = c.db.Exec(insertQrcodeRecord, device.ID.String(), noiseKeyPub, identityKeyPub, advKey, 1)
	if err != nil {
		fmt.Println("Save qrcode result fail ")
	}

	if !device.Initialized {
		innerStore := NewSQLStore(c, *device.ID)
		device.Identities = innerStore
		device.Sessions = innerStore
		device.PreKeys = innerStore
		device.SenderKeys = innerStore
		device.AppStateKeys = innerStore
		device.AppState = innerStore
		device.Contacts = innerStore
		device.ChatSettings = innerStore
		device.MsgSecrets = innerStore
		device.PrivacyTokens = innerStore
		device.Initialized = true
	}
	return err
}

func baseEncodeKeys(device *store.Device) (nkp, ikp, ak string) {
	noiseKeyPub := base64.StdEncoding.EncodeToString(device.NoiseKey.Pub[:])
	identityKeyPub := base64.StdEncoding.EncodeToString(device.IdentityKey.Pub[:])
	advKey := base64.StdEncoding.EncodeToString(device.AdvSecretKey)
	return noiseKeyPub, identityKeyPub, advKey
}

// DeleteDevice deletes the given device from this database. This should be called through Device.Delete()
func (c *Container) DeleteDevice(store *store.Device) error {
	if store.ID == nil {
		return ErrDeviceIDMustBeSet
	}
	_, err := c.db.Exec(deleteDeviceQuery, store.ID.String())
	return err
}

// DisableSubjectDeviceByJidUser 停用用户指定账号的设备
func (c *Container) DisableSubjectDeviceByJidUser(store *store.Device) error {
	if store.ID == nil {
		return ErrDeviceIDMustBeSet
	}
	_, err := c.db.Exec(disableDeviceQuery, store.ID.User, store.SubjectId)
	return err
}

func (c *Container) GetDeviceByJidUser(jid string) (*store.Device, error) {
	devices, err := c.GetDeviceByJidUserExc(jid)
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		//return c.NewDevice(), nil
		return nil, nil
	} else {
		return devices[0], nil
	}
}

func (c *Container) GetDeviceByJidUserExc(jid string) ([]*store.Device, error) {
	res, err := c.db.Query(getDeviceByJidUserQuery, jid)
	if err != nil {
		return nil, fmt.Errorf("failed to query sessions: %w", err)
	}
	sessions := make([]*store.Device, 0)
	for res.Next() {
		sess, scanErr := c.scanDevice(res)
		if scanErr != nil {
			return sessions, scanErr
		}
		sessions = append(sessions, sess)
	}
	return sessions, nil
}

const (
	insertQrcodeRecord = `
		INSERT INTO whatsmeow_qrcode_record (jid, noise_key_pub,identity_key_pub,adv_secret_key,scan_state)
		VALUES (?, ?, ?, ?, ?)
	`
	hasScanQrcode = `select jid FROM whatsmeow_qrcode_record WHERE noise_key_pub=? and identity_key_pub=? and adv_secret_key=? and deleted = 0 `

	deleteQrcodeRecord = `update whatsmeow_qrcode_record set deleted = 1 where
      identity_key_pub=? and identity_key_pub=? and adv_secret_key=?`
)

func (c *Container) HasScanQrcode(noiseKeyPub, identityKeyPub, advSecret string) (jid string, err error) {
	err = c.db.QueryRow(hasScanQrcode, noiseKeyPub, identityKeyPub, advSecret).Scan(&jid)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return jid, nil
}

const (
	insertCheckUserRecord = `
		INSERT INTO whatsmeow_check_user_record (phone, check_result)
		VALUES (?, ?)
		ON DUPLICATE KEY UPDATE check_result=?`
)

// PutCheckUser 保存检测用户结果
func (c *Container) PutCheckUser(results []*store.CheckUserResult) error {
	tx, _ := c.db.Begin()
	for i := range results {
		_, err := c.db.Exec(insertCheckUserRecord, results[i].Phone, results[i].Result, results[i].Result)
		if err != nil {
			return fmt.Errorf("failed to PutCheckUser: %w", err)
		}
	}
	tx.Commit()
	return nil
}

// GetCheckUserResult 获取检测用户结果
func (c *Container) GetCheckUserResult(phones []string) ([]*store.CheckUserResult, error) {
	phoneStr := strings.Join(phones, "','")
	sqlText := "select phone, check_result  from whatsmeow_check_user_record where phone in  ('%s')"
	sqlText = fmt.Sprintf(sqlText, phoneStr)
	res, err := c.db.Query(sqlText)
	if err != nil {
		return nil, fmt.Errorf("failed to getCheckUserResult: %w", err)
	}
	results := make([]*store.CheckUserResult, 0)
	for res.Next() {
		var phone string
		var check bool
		result := &store.CheckUserResult{}
		scanErr := res.Scan(&phone, &check)
		if scanErr != nil {
			return results, scanErr
		}
		result.Phone = phone
		result.Result = check
		results = append(results, result)
	}
	return results, nil
}
