/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.engineering.efficiency.patch.analysis.api;

import org.apache.log4j.Logger;
import org.wso2.engineering.efficiency.patch.analysis.Configuration;
import org.wso2.engineering.efficiency.patch.analysis.exceptions.PatchAnalysisConfigurationException;
import org.wso2.msf4j.security.basic.AbstractBasicAuthSecurityInterceptor;

import java.util.Objects;

/**
 * Authenticating the micro service with Basic Auth via username and password.
 */
public class AuthInterceptor extends AbstractBasicAuthSecurityInterceptor {

    private static final Logger LOGGER = Logger.getLogger(AuthInterceptor.class);

    @Override
    protected boolean authenticate(String username, String password) {

        try {
            Configuration configuration = Configuration.getInstance();
            LOGGER.info(configuration.getAppUsername());
            return Objects.equals(username, configuration.getAppUsername()) && Objects.equals(password,
                    configuration.getAppPassword());
        } catch (PatchAnalysisConfigurationException e) {
            LOGGER.error("Could not read config file values.", e);
        }
        return false;
    }
}
