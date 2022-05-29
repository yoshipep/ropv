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
    struct hashtable_t *table2 = create(2);
    insert(&table, &x, "Abeja");
    insert(&table, &x, "Bebe");
    insert(&table, &x, "Casa");
    insert(&table, &x, "Danone");
    insert(&table, &x, "Elefante");
    printContent(table);
    puts("");
    insert(&table, &x, "Falta");
    insert(&table, &x, "Gol");
    insert(&table, &x, "Huno");
    int *y = insert(&table, &x, "Indigente");
    if (NULL == y)
    {
        insert(&table, &x, "Indigente");
    }
    insert(&table, &x, "Jaime");
    insert(&table, &x, "Kase");
    printContent(table);
    destroy(table);
    insert(&table2, &x, "XX");
    puts("");
    printContent(table2);
    destroy(table2);
}