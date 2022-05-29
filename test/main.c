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
#include <stdio.h>

#include "hashtable.h"

int main()
{
    int x = 3;
    struct hashtable_t *table = create(10);
    insert(&table, &x, (unsigned char *)"Abeja");
    insert(&table, &x, (unsigned char *)"Bebe");
    insert(&table, &x, (unsigned char *)"Casa");
    insert(&table, &x, (unsigned char *)"Danone");
    insert(&table, &x, (unsigned char *)"Elefante");
    printContent(table);
    puts("");
    insert(&table, &x, (unsigned char *)"Falta");
    insert(&table, &x, (unsigned char *)"Gol");
    insert(&table, &x, (unsigned char *)"Huno");
    int *y = insert(&table, &x, (unsigned char *)"Indigente");
    if (NULL == y)
    {
        insert(&table, &x, (unsigned char *)"Indigente");
    }
    insert(&table, &x, (unsigned char *)"Jaime");
    insert(&table, &x, (unsigned char *)"Kase");
    printContent(table);
}