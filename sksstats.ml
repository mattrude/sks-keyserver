(************************************************************************)
(* This file is part of SKS.  SKS is free software; you can
   redistribute it and/or modify it under the terms of the GNU General
   Public License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
   USA *)
(***********************************************************************)

open StdLabels
open MoreLabels
open Printf
open Common
open DbMessages
open Packet

let settings = {
    Keydb.withtxn = !Settings.transactions;
    Keydb.cache_bytes = !Settings.cache_bytes;
    Keydb.pagesize = !Settings.pagesize;
    Keydb.keyid_pagesize = !Settings.keyid_pagesize;
    Keydb.meta_pagesize = !Settings.meta_pagesize;
    Keydb.subkeyid_pagesize = !Settings.subkeyid_pagesize;
    Keydb.time_pagesize = !Settings.time_pagesize;
    Keydb.tqueue_pagesize = !Settings.tqueue_pagesize;
    Keydb.word_pagesize = !Settings.word_pagesize;
    Keydb.dbdir = Lazy.force Settings.dbdir;
    Keydb.dumpdir = Lazy.force Settings.dumpdir;
  }

module Keydb = Keydb.Unsafe

let get_algo key file =
   let fpr = Fingerprint.fp_from_key key in
   let packet = List.filter (fun x -> x.packet_type = Public_Key_Packet) key in
   if List.length packet > 0 then
   (let packet = List.hd packet in
   let pki = ParsePGP.parse_pubkey_info packet in
   fprintf file "%s;%d;%d;%d\n" (KeyHash.hexify fpr) pki.pk_version pki.pk_alg pki.pk_keylen)

let () =
    perror "sksstats (SKS %s%s)" Common.version Common.version_suffix;
    Keydb.open_dbs settings;
    let file = "sksstats.dat" in
    let out = open_out file in 

    let generate_stats =
      let genstat ~hash ~keystr =
        let skey = Keydb.skey_of_string keystr in
        if not (Keydb.skey_is_offset skey) then
          let key = Keydb.key_of_skey skey in
          get_algo key out;
      in
      Keydb.raw_iter genstat in

    generate_stats;
    close_out out;
    Keydb.close_dbs ();

