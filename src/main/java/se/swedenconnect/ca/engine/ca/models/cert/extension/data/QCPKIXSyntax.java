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

package se.swedenconnect.ca.engine.ca.models.cert.extension.data;

import lombok.Getter;
import se.swedenconnect.cert.extensions.data.SemanticsInformation;

/**
 * Class holding data about Qualified Certificate Statements syntax version and semantics information in accordance with
 * RFC 3739
 *
 * <code>
 * qcStatement-2 QC-STATEMENT ::= { SYNTAX SemanticsInformation
 * IDENTIFIED BY id-qcs-pkixQCSyntax-v2 }
 * --  This statement identifies conformance with requirements
 * --  defined in this Qualified Certificate profile
 * --  (Version 2). This statement may optionally contain
 * --  additional semantics information as specified below.
 *
 * SemanticsInformation ::= SEQUENCE {
 * semanticsIdentifier        OBJECT IDENTIFIER   OPTIONAL,
 * nameRegistrationAuthorities NameRegistrationAuthorities
 * OPTIONAL }
 * (WITH COMPONENTS {..., semanticsIdentifier PRESENT}|
 * WITH COMPONENTS {..., nameRegistrationAuthorities PRESENT})
 *
 * NameRegistrationAuthorities ::=  SEQUENCE SIZE (1..MAX) OF GeneralName
 * </code>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class QCPKIXSyntax {

  @Getter private final Version version;
  @Getter private SemanticsInformation semanticsInformation;

  /**
   * Constructor for syntax version declaration without semantics information
   *
   * @param version PKIXSyntax version (1 or 2)
   */
  public QCPKIXSyntax(Version version) {
    this.version = version;
  }

  /**
   * Constructor for default version 2 with semantics information
   *
   * @param semanticsInformation semantics information
   */
  public QCPKIXSyntax(SemanticsInformation semanticsInformation) {
    this.version = Version.V2;
    this.semanticsInformation = semanticsInformation;
  }

  /**
   * Constructor setting version and semantics information
   *
   * @param version              version
   * @param semanticsInformation semantics information
   */
  public QCPKIXSyntax(Version version, SemanticsInformation semanticsInformation) {
    this.version = version;
    this.semanticsInformation = semanticsInformation;
  }

  /**
   * Enumeration of versions of QC extension syntax
   */
  public enum Version {
    /** Version 1 */
    V1,
    /** Version 2 */
    V2;
  }

}
