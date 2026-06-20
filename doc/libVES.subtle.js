/***************************************************************************
 *          ___       ___
 *         /   \     /   \    VESvault
 *         \__ /     \ __/    Encrypt Everything without fear of losing the Key
 *            \\     //                   https://vesvault.com https://ves.host
 *             \\   //
 *     ___      \\_//
 *    /   \     /   \         libVES.subtle.js
 *    \__ /     \ __/         Manage and share e2e encrypted items
 *       \\     //            Real time event tracking
 *        \\   //             VES PKI and e2e Key Exchange
 *         \\_//              VES Redundancies and Key Recovery
 *         /   \
 *         \___/
 *
 *
 * (c) 2025 VESvault Corp
 * Jim Zubov <jz@vesvault.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License in the accompanying LICENSE
 * file, or at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
 ***************************************************************************/

/***************************************************************************
 * @type libVES.Vault
 * libVES.subtle Vault Factory
 * Use "demo" for the public shared VES demo domain
 * Use "x-*" to create your own experimental domain
 * @returns libVES.Vault
 ***************************************************************************/
let vesDomain = 'demo'
let vault = libVES.subtle(vesDomain)

/***************************************************************************
 * Unlock the Vault
 ***************************************************************************/
// Unlock a User App Vault using an interactive browser popup
await vault.unlock()

// OR, unlock a User App Vault using locally stored credentials. Make sure
// the credentials are stored securely
let credentialUri = 'ves://:demo@demo/demo/'
await vault.unlock(credentialUri)

// OR, unlock an Anonymous App Vault using a secret passPhrase. The Vault ID
// is uniquely generated from the passphrase.
let passPhrase = 'passphrase'
await vault.anonymous(passPhrase)

// Check if the Vault is unlocked
let isUnlocked = await vault.unlocked()

/***************************************************************************
 * Get an array of all items stored in the vault
 * @returns Promise(Array(libVES.Item))
 ***************************************************************************/
let items = await vault.items()

/***************************************************************************
 * Create an Item instance
 * @returns libVES.Item
 ***************************************************************************/
// Create an instance of an item with a specified itemId
let itemId = 'my-test-item'
let item = vault.item(itemId)

// Create an instance of an item with an automatically assigned itemId
let item = vault.item()

/***************************************************************************
 * Start real time event tracking.
 * Call vault.addEventListener() or define vault.on* event handlers prior to
 * the following call. The handlers are invoked with libVES.CustomEvent
 ***************************************************************************/
// Start tracking future events without replaying the event history
await vault.start()

// Or, start tracking and replay the past events starting with nextId.
// Use nextId = 0 to replay all history from the beginning.
let nextId = 0
await vault.start(nextId)

// Or, start tracking and replay the short history that includes only
// currently existing items
await vault.start(false)

/***************************************************************************
 * Stop real time event tracking
 ***************************************************************************/
vault.stop()

/***************************************************************************
 * Get the special Item that stores the VESkey (passphrase) to the Vault.
 * The VESkey can be retrieved using item.get() is it is decryptable by the
 * unlocked Vault.
 * @returns Promise(libVES.Item)
 ***************************************************************************/
let item = await vault.password()

/***************************************************************************
 * Get the list of dependent Vaults that are directly unlockable by the
 * current Vault.
 * @returns Promise(Array(libVES.Vault))
 ***************************************************************************/
let subVaults = await vault.vaults()

/***************************************************************************
 * Create an instance of the specific Vault. The vaultId can be a VES URI
 * or a short ID. Use the owner's email address to reference a Vault within
 * the current VES Domain owned by the specific user.
 * @returns libVES.Vault
 ***************************************************************************/
let vaultId = 'user@acme.com'
let subVault = vault.vault(vaultId)

/***************************************************************************
 * Verify the status of the Vault. This call returns a Promise that resolves
 * to the current vault on success, or throws libVES.Error.
 * The call populates vault.current and vault.owned
 * @returns Promise(libVES.Vault)
 ***************************************************************************/
let vault = await subVault.verify()

/***************************************************************************
 * The following propertiest indicate the status of the Vault. The properies
 * are populated by vault.unlock(), vault.verify(), and in the Vaults
 * returned by item.share()
 ***************************************************************************/
// The Vault currently exists, and is not in a Lost status
// @type boolean
vault.current

// The Vault/Subvault is owned by the unlocked Vault.
// @type boolean
vault.owner

// The Vault has an Admin permission on the Item. This property is populated
// only in the Vaults returned by item.share()
// @type boolean
vault.admin

/***************************************************************************
 * Get a VES URI that idenitfies the Vault.
 * @returns string
 ***************************************************************************/
vault.uri()

/***************************************************************************
 * Get a short identifier of the Vault. Note that the short identifier is
 * specific to the selected VES domain. Use vault.uri() to get a full
 * identifier that includes the VES domain.
 * @returns string
 ***************************************************************************/
vault.short()

/***************************************************************************
 * Lock the Vault
 ***************************************************************************/
// Set the lock timeout in seconds. The Vault will be automatically locked
// when the timeout expires. Register a handler for an "authexpire" event to
// catch the expiration before the Vault is locked.
// Any call to this function overrides the previously set timeout.
let tmOut = 300
vault.lock(tmOut)

// Lock the Vault immediately
vault.lock()

/***************************************************************************
 * @type libVES.Item
 * Store a value in the item. The value is stored in the VES Repository an
 * e2e encrypted form.
 ***************************************************************************/
let itemValue = 'secret'
await item.put(itemValue)

/***************************************************************************
 * Retrieve the value stored in the item
 * @returns Promise(string)
 ***************************************************************************/
let itemValue = await item.get()

/***************************************************************************
 * Manage the item sharing with other vaults in an e2e encrypted form
 ***************************************************************************/
// Share the item with other vaults, keep any existing sharing
let vaultIds = ['user@acme.com']
await item.add(vaultIds)

// Remove sharing with the specified Vaults.
// Note: The current Vault can be removed if it doesn't own the Item.
// Removing will make the Item unaccessible through the current Vault,
// unless shared again by the Item owner.
let vaultIds = ['user@acme.com']
await item.remove(vaultIds)

// Replace the list of vaults the Item is shared with. The current Vault is
// added automatically if not included.
let vaultIds = ['user@acme.com']
await item.share(vaultIds)

// Get the list of vaults the Item is currently shared with
// @returns Promise(Array(libVES.Vault))
let shares = await item.share()

// Check whether the item is shared with a specific Vault. Returns null if
// not shared.
// @returns Promise(libVES.Vault)
let vaultId = 'user@acme.com'
let theShare = await item.shareFor(vaultId)

/***************************************************************************
 * Check if the item currently exists and was not deleted.
 * @returns boolean
 ***************************************************************************/
let exists = await item.exists()

/***************************************************************************
 * Delete the item. The item ID can be reused for another item.
 ***************************************************************************/
await item.delete()

/***************************************************************************
 * Start real time event tracking.
 * Call item.addEventListener() or define item.on* event handlers prior to
 * the following call. The handlers are invoked with libVES.CustomEvent
 ***************************************************************************/

// Start tracking future events without replaying the event history
await item.start()

// Or, start tracking and replay the past events starting with nextId.
// Use nextId = 0 to replay all history from the beginning.
let nextId = 0
await item.start(nextId)

// Or, start tracking and replay the short history that includes only
// the Vaults the Item is currently shared with
await item.start(false)

/***************************************************************************
 * Stop real time event tracking
 ***************************************************************************/
item.stop()

/***************************************************************************
 * Get a VES URI that idenitfies the Item.
 * @returns string
 ***************************************************************************/
item.uri()

/***************************************************************************
 * Get a short identifier of the Item. Note that the short identifier is
 * specific to the selected VES domain. Use item.uri() to get a full
 * identifier that includes the VES domain.
 * @returns string
 ***************************************************************************/
item.short()

/***************************************************************************
 * Check if the Item value can be retrieved and decrypted by the currently
 * unlocked Vault.
 * @returns boolean
 ***************************************************************************/
let isReadable = await item.readable()

/***************************************************************************
 * Check if the Item value can be overwritten by the currently unlocked
 * Vault.
 * @returns boolean
 ***************************************************************************/
let isWritable = await item.writable()

/***************************************************************************
 * Use the Item as a stream cipher for encrypting and decrypting arbitrary
 * data. If the Item is used for a cipher, the cipher key is stored in the
 * VES repository in an e2e encrypted form, and the Item cannot store any
 * other value.
 * @returns Promise(libVES.ItemCipher)
 ***************************************************************************/
let itemCipher = await item.cipher()


/***************************************************************************
 * @type libVES.ItemCipher
 * A stream cipher for encrypting arbitrary data. The cipher key is stored
 * in the VES Repository in an e2e encrypted form. The data encrypted by
 * the cipher can be stored at any external storage. The default cipher
 * algorithm is AES256GCM1K, a VES implementation based on AES-256 GCM.
 * The plaintext and ciphertext data can be ArrayBuffer, Uint*Array,
 * Int*Array, Blob or string. The type of the return value of encrypt() and
 * decrypt() conforms to the type of the input value. If the type is string,
 * the ciphertext is Base64 encoded.
 ***************************************************************************/
// Encrypt the data
let plainText = 'The secret text'
let cipherText = await itemCipher.encrypt(plainText)

// Decrypt the data
let plainText = await itemCipher.decrypt(cipherText)

/***************************************************************************
 * An arbitrary metadata object associated with the cipher. The metadata is
 * stored in the VES Repository in an e2e encrypted form along with the
 * cipher key.
 ***************************************************************************/
// Store metadata
let cipherMeta = {myValue: 'Metadata String'}
await itemCipher.meta(cipherMeta)

// Retrieve metadata
let cipherMeta = await itemCipher.meta()


/***************************************************************************
 * @type libVES.CustomEvent
 * An event related to a Vault or an Item, current or hitorical. VES stores
 * a history of essential events for all objects.
 *
 * Event types:
 * "authexpire"    : the Vault will be imminently locked unless an action
 *                   is taken. The event handler may call vault.lock(tmOut)
 *                   to extend the unlocked time by tmOut seconds. This
 *                   event is real time only, not stored in the history
 * "vaultcreate"   : a Vault is created
 * "vaultadd"      : the Item that stores the passphrase to a Vault is
 *                   shared with another Vault
 * "vaultremove"   : the Item that stores the passphrase to a Vault is
 *                   unshared with another Vault
 * "itemcreate"    : an Item is created
 * "itemadd"       : an Item is shared with a Vault
 * "itemremove"    : an Item is unshared with a Vault
 * "itemdelete"    : an Item is deleted
 * "itemchange"    : an Item has been changed. This event is delivered to
 *                   each Vault the Item is shared with that are currently
 *                   listening to real time events. The event does not
 *                   have historical value and is not guaranteed to be
 *                   permanently stored by VES.
 * "olditemadd"    : a historical (deleted) version of the Item is shared
 *                   with a Vault. Historical versions are not guaranteed
 *                   to be permanently stored in the VES Repository.
 * "olditemremove" : a historical version of the Item is unshared with a
 *                   Vault
 * "sessioncreate" : the vault has been unlocked, a new session is created
 ***************************************************************************/
vesEvent.type

/***************************************************************************
 * Event details dictionary
 ***************************************************************************/
vesEvent.detail

// @type libVES.Item
// The Item pertaining to the Event. Populated for "item*" and "olditem*"
// event types.
vesEvent.detail.item

// @type libVES.Vault
// The Vault pertaining to the event that the Item was shared or unshared
// with. Populated for "*add" and "*remove" event types.
vesEvent.detail.share

// @type libVES.Vault
// The Vault pertaining to the Event, the passphrase Item to which was
// shared or unshared with another Vault, or an action was taken on.
// Populated for "vault*" and "authexpire" event types.
vesEvent.detail.vault

// @type libVES.Author
// The Session that authored the changes triggering the Event
let vesSession = vesEvent.detail.author

// @type libVES.Author
// The Session subject to the Event. Populated only for "session*" event
// types.
let vesSession = vesEvent.detail.session

// @type int
// A unique numeric ID of the Event. Not populated on provisional Events
// (when replay == true).
vesEvent.detail.id

// @type Date
// The timestamp of the Event. Not populated on provisional Events (when
// replay == true).
vesEvent.detail.at

// @type boolean
// If set to true, the Event is provisional, and does not correspond to
// any Event stored in VES. Provisional events are generated by
// vault.start(false) or item.start(false) to replay the short history
// that leads to the current state of the Vault / Item.
vesEvent.detail.replay

/***************************************************************************
 * @type libVES.Author
 * A VES session pertaining to an authenticated App Vault or to a VES User.
 * The details of the session can only be retrieved by a Session with the
 * same owner. Historical Session details are not guaranteed to be
 * permanently stored in VES.
 ***************************************************************************/

// @type int
// A unique numeric Session ID
vesSession.sessid

// @type libVES.Vault
// The Vault that is authorized for the Session
vesSession.vault

// @type string
// An IPv4 or IPv6 address of the creator of the Session
vesSession.remote

// @type string
// A User Agent string passed to the API call that created the Session
vesSession.userAgent
