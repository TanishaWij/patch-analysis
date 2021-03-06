/*
Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
WSO2 Inc. licenses this file to you under the Apache License,
Version 2.0 (the "License"); you may not use this file except
in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
*/

package org.wso2.engineering.patchanalysis.client.services;

import org.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet to act as a router between the backend microservice and the frontend.
 */
public class RouterService extends HttpServlet {

    private static final Logger log = LoggerFactory.getLogger(RouterService.class);

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {

        try (PrintWriter out = resp.getWriter()) {
            resp.setContentType("application/json");
            out.print(ServiceExecutor.executeGetService(req.getPathInfo()));
        } catch (JSONException e) {
            log.error("Failed to get the response from the backend service. " + e.getMessage(), e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {

        try (PrintWriter out = resp.getWriter()) {
            resp.setContentType("application/json");
            out.print(ServiceExecutor.executePostService(req.getPathInfo(), req.getReader().readLine(), true));
        } catch (JSONException | IOException e) {
            log.error("Failed to get the response from the backend service. " + e.getMessage(), e);
        }
    }
}
