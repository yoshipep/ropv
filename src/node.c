/*
 * Copyright (C) 2022 Josep Comes Sanchis
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "gadget.h"
#include "node.h"

struct gadget_t *del(struct node_t *list, const char *key)
{
	if (NULL == list)
		return NULL;
	struct gadget_t *res;
	struct node_t *head = list, *last = NULL;
	while ((NULL != head->data) && (0 != strcmp(head->key, key))) {
		last = head;
		head = head->next;
	}
	if (NULL == last) {
		res = head->data;
		list = list->next;
		free(head);
		head = NULL;
		return res;
	}
	if ((NULL == head->data) && (0 == strcmp(last->key, key))) {
		free(head);
		head = NULL;
		return last->data;
	} else if (NULL == head->data) {
		return NULL;
	}
	res = head->data;
	last->next = head->next;
	free(head);
	head = NULL;
	return res;
}

struct node_t *find(struct node_t *list, const char *key)
{
	if (NULL == list)
		return NULL;
	struct node_t *head = list;
	while (NULL != head->data) {
		if (0 == strcmp(head->key, key))
			return head;
		head = head->next;
	}
	return NULL;
}

struct node_t *insert(struct node_t *list, struct gadget_t *data,
		      const char *key)
{
	list->key = strdup(key);
	list->data = data;
	list->next = create();
	return list->next;
}

void printContent(struct node_t *list)
{
	if (NULL == list)
		return;
	struct node_t *head = list;
	while (NULL != head->data) {
		printGadget(head->data);
		head = head->next;
	}
}
