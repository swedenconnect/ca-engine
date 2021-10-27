/*
 * Copyright (c) 2021. Agency for Digital Government (DIGG)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package se.swedenconnect.ca.cmc.api.data;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;

import java.util.Arrays;
import java.util.Optional;

/**
 * Enumeration of CMC Control object identifiers
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
@AllArgsConstructor
@Slf4j
public enum CMCControlObjectID {
  statusInfo(CMCObjectIdentifiers.id_cmc_statusInfo),
  identification(CMCObjectIdentifiers.id_cmc_identification),
  identityProof(CMCObjectIdentifiers.id_cmc_identityProof),
  dataReturn(CMCObjectIdentifiers.id_cmc_dataReturn),
  transactionId(CMCObjectIdentifiers.id_cmc_transactionId),
  senderNonce(CMCObjectIdentifiers.id_cmc_senderNonce),
  recipientNonce(CMCObjectIdentifiers.id_cmc_recipientNonce),
  addExtensions(CMCObjectIdentifiers.id_cmc_addExtensions),
  encryptedPOP(CMCObjectIdentifiers.id_cmc_encryptedPOP),
  decryptedPOP(CMCObjectIdentifiers.id_cmc_decryptedPOP),
  lraPOPWitness(CMCObjectIdentifiers.id_cmc_lraPOPWitness),
  getCert(CMCObjectIdentifiers.id_cmc_getCert),
  getCRL(CMCObjectIdentifiers.id_cmc_getCRL),
  revokeRequest(CMCObjectIdentifiers.id_cmc_revokeRequest),
  regInfo(CMCObjectIdentifiers.id_cmc_regInfo),
  responseInfo(CMCObjectIdentifiers.id_cmc_responseInfo),
  queryPending(CMCObjectIdentifiers.id_cmc_queryPending),
  popLinkRandom(CMCObjectIdentifiers.id_cmc_popLinkRandom),
  popLinkWitness(CMCObjectIdentifiers.id_cmc_popLinkWitness),
  popLinkWitnessV2(CMCObjectIdentifiers.id_cmc_popLinkWitnessV2),
  confirmCertAcceptance(CMCObjectIdentifiers.id_cmc_confirmCertAcceptance),
  statusInfoV2(CMCObjectIdentifiers.id_cmc_statusInfoV2),
  trustedAnchors(CMCObjectIdentifiers.id_cmc_trustedAnchors),
  authData(CMCObjectIdentifiers.id_cmc_authData),
  batchRequests(CMCObjectIdentifiers.id_cmc_batchRequests),
  batchResponses(CMCObjectIdentifiers.id_cmc_batchResponses),
  publishCert(CMCObjectIdentifiers.id_cmc_publishCert),
  modCertTemplate(CMCObjectIdentifiers.id_cmc_modCertTemplate),
  controlProcessed(CMCObjectIdentifiers.id_cmc_controlProcessed),
  identityProofV2(CMCObjectIdentifiers.id_cmc_identityProofV2);


  private ASN1ObjectIdentifier oid;

  /**
   * Return the Enum instance of the CMC Control object identifier matching a specified ASN OID
   * @param oid ASN.1 OID
   * @return Enum instance if match found, or else null
   */
  public static CMCControlObjectID getControlObjectID(String oid){
    try {
      return getControlObjectID(new ASN1ObjectIdentifier(oid));
    } catch (Exception ex){
      log.debug("Illegal Object Identifier: {}", ex.toString());
      return null;
    }
  }

  /**
   * Return the Enum instance of the CMC Control object identifier matching a specified ASN OID
   * @param oid ASN.1 OID
   * @return Enum instance if match found, or else null
   */
  public static CMCControlObjectID getControlObjectID(ASN1ObjectIdentifier oid){
    return Arrays.stream(values())
      .filter(cmcControlObjectID -> cmcControlObjectID.getOid().equals(oid))
      .findFirst()
      .orElse(null);
  }

}
