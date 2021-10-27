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
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmc.CMCFailInfo;
import org.bouncycastle.asn1.cmc.CMCStatus;

import java.util.Arrays;

/**
 * Enumeration of CMC fail types
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@AllArgsConstructor
@Getter
@Slf4j
public enum CMCFailType {

  badAlg(CMCFailInfo.badAlg, 0),
  badMessageCheck(CMCFailInfo.badMessageCheck, 1),
  badRequest(CMCFailInfo.badRequest, 2),
  badTime(CMCFailInfo.badTime, 3),
  badCertId(CMCFailInfo.badCertId, 4),
  confirmRequired(CMCFailInfo.unsupportedExt, 5),
  mustArchiveKeys(CMCFailInfo.mustArchiveKeys, 6),
  partial(CMCFailInfo.badIdentity, 7),
  popRequired(CMCFailInfo.popRequired, 8),
  popFailed(CMCFailInfo.popFailed, 9),
  noKeyReuse(CMCFailInfo.noKeyReuse, 10),
  internalCAError(CMCFailInfo.internalCAError, 11),
  tryLater(CMCFailInfo.tryLater, 12),
  authDataFail(CMCFailInfo.authDataFail, 13);

  private CMCFailInfo cmcFailInfo;
  private int value;

  /**
   * Get CMCFailInfoType from integer value
   * @param value the integer value of a CMC Fail Info according to RFC 5272
   * @return {@link CMCFailType}
   */
  public static CMCFailType getCMCFailType(int value){
    return Arrays.stream(values())
      .filter(cmcStatusType -> cmcStatusType.getValue() == value)
      .findFirst()
      .orElse(null);
  }

  /**
   * Get CMCFailType from CMCFailInfo value
   * @param cmcFailInfo CMCFailInfo value
   * @return {@link CMCFailType}
   */
  public static CMCFailType getCMCFailType(CMCFailInfo cmcFailInfo){
    try {
      int intVal = ((ASN1Integer) cmcFailInfo.toASN1Primitive()).intPositiveValueExact();
      return getCMCFailType(intVal);
    } catch (Exception ex) {
      log.debug("Bad CMCFailInfo syntax", ex);
      return null;
    }
  }

}
