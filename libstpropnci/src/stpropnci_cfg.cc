/******************************************************************************
 *
 *  Copyright (C) 2025 STMicroelectronics
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <stpropnci-internal.h>

#ifndef STPROPNCI_VENDOR
std::string nfc_storage_path = "/data/nfc";
#else
std::string nfc_storage_path = "/data/vendor/nfc";
#endif

const char* sConfigFile = "/stpropnci_cfg.xml";

/*******************************************************************************
**
** Function         stpropnci_cfg_write_value
**
** Description      Write to stpropnci configuration file
**
** Params:
**   - child_name :  Name of the child node to write
**   - value      :  Value to write to the child node
**
** Returns
**
*******************************************************************************/
void stpropnci_cfg_write_value(const std::string& child_name,
                               const std::string& value) {
  std::string strFilename(nfc_storage_path);
  strFilename += sConfigFile;

  xmlDocPtr doc = xmlParseFile(strFilename.c_str());
  xmlNodePtr root_node = nullptr;

  if (doc == NULL) {
    // File does not exist, create new doc and root
    doc = xmlNewDoc(BAD_CAST "1.0");
    root_node = xmlNewNode(NULL, BAD_CAST "stpropnci_cfg");
    xmlDocSetRootElement(doc, root_node);
  } else {
    root_node = xmlDocGetRootElement(doc);
    if (!root_node ||
        xmlStrcmp(root_node->name, BAD_CAST "stpropnci_cfg") != 0) {
      // Invalid root, recreate
      xmlFreeDoc(doc);
      doc = xmlNewDoc(BAD_CAST "1.0");
      root_node = xmlNewNode(NULL, BAD_CAST "stpropnci_cfg");
      xmlDocSetRootElement(doc, root_node);
    }
  }

  // Search for the child node
  xmlNodePtr child = root_node->xmlChildrenNode;
  xmlNodePtr targetNode = nullptr;
  while (child) {
    if (xmlStrcmp(child->name, BAD_CAST child_name.c_str()) == 0) {
      targetNode = child;
      break;
    }
    child = child->next;
  }

  if (targetNode) {
    // Update value
    xmlNodeSetContent(targetNode, BAD_CAST value.c_str());
  } else {
    // Create node
    xmlNewChild(root_node, NULL, BAD_CAST child_name.c_str(),
                BAD_CAST value.c_str());
  }

  // Save the document
  xmlSaveFormatFileEnc(strFilename.c_str(), doc, "UTF-8", 1);

  xmlFreeDoc(doc);
  xmlCleanupParser();
}

/*******************************************************************************
 **
 ** Function         stpropnci_cfg_read_value
 **
 ** Description      Read from stpropnci configuration file
 **
 ** Params:
 **   - child_name :  Name of the child node to read
 **
 ** Returns          Value of the child node, or empty string if not found
 **
 *******************************************************************************/
std::string stpropnci_cfg_read_value(const std::string& child_name) {
  std::string strFilename(nfc_storage_path);
  strFilename += sConfigFile;

  xmlDocPtr doc = xmlParseFile(strFilename.c_str());
  if (doc == NULL) {
    LOG_D("no file stored");
    return "";
  }

  xmlNodePtr root_node = xmlDocGetRootElement(doc);
  if (root_node == NULL) {
    LOG_E("fail root element");
    xmlFreeDoc(doc);
    return "";
  }

  xmlNodePtr child = root_node->xmlChildrenNode;
  while (child) {
    if (xmlStrcmp(child->name, BAD_CAST child_name.c_str()) == 0) {
      xmlChar* value = xmlNodeGetContent(child);
      if (value) {
        std::string result((const char*)value);
        xmlFree(value);
        xmlFreeDoc(doc);
        xmlCleanupParser();
        LOG_D("read %s=%s", child_name.c_str(), result.c_str());
        return result;
      }
    }
    child = child->next;
  }

  xmlFreeDoc(doc);
  xmlCleanupParser();
  LOG_D("read %s: not found", child_name.c_str());
  return "";
}
